import express from "express";
import cors from "cors";
import { Pool } from "pg";
import { CognitoJwtVerifier } from "aws-jwt-verify";
import {
    S3Client,
    PutObjectCommand,
    GetObjectCommand,
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

// ---- env ----
const {
    PORT = "3002",
    // DB
    DB_HOST,
    DB_PORT = "5432",
    DB_NAME = "postgres",
    DB_USER = "postgres",
    DB_PASSWORD,
    // Auth
    COGNITO_USER_POOL_ID,
    COGNITO_CLIENT_ID,
    // S3
    S3_BUCKET,
    S3_REGION = process.env.AWS_REGION || "ap-south-1",
    S3_PREFIX = "classrooms", // we'll layout keys under this prefix
} = process.env;

// ---- setup ----
const app = express();
app.use(
    cors({
        origin: "*",
        methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization"],
    })
);
app.use(express.json());

const pool = new Pool({
    host: DB_HOST,
    port: +DB_PORT,
    database: DB_NAME,
    user: DB_USER,
    password: DB_PASSWORD,
    ssl: { rejectUnauthorized: false },
    max: 8,
});

if (!COGNITO_USER_POOL_ID) {
    console.error("COGNITO_USER_POOL_ID required");
    process.exit(1);
}
const verifier = CognitoJwtVerifier.create({
    userPoolId: COGNITO_USER_POOL_ID,
    tokenUse: "access",
    clientId: COGNITO_CLIENT_ID || undefined,
});

const s3 = new S3Client({ region: S3_REGION });

async function auth(req, res, next) {
    const hdr = req.headers.authorization || "";
    const token = hdr.startsWith("Bearer ") ? hdr.slice(7) : null;
    if (!token) return res.status(401).json({ error: "Missing token" });
    try {
        const payload = await verifier.verify(token);
        req.user = { sub: payload.sub, email: payload.email || null };
        next();
    } catch (e) {
        console.error("JWT verify failed:", e?.message || e);
        return res.status(401).json({ error: "Invalid token" });
    }
}

async function loadUser(req, res, next) {
    const { rows } = await pool.query(
        "SELECT id, role FROM app.users WHERE cognito_sub=$1",
        [req.user.sub]
    );
    if (!rows.length)
        return res.status(403).json({ error: "User not found in DB" });
    req.user.dbId = rows[0].id;
    req.user.role = rows[0].role;
    next();
}

async function isMemberOf(classroomId, userId) {
    const { rows } = await pool.query(
        "SELECT role_in_class FROM app.memberships WHERE classroom_id=$1 AND user_id=$2",
        [classroomId, userId]
    );
    return rows[0]?.role_in_class || null;
}

function safeName(name) {
    return (name || "file").replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 128);
}

app.get("/health", (_req, res) => res.json({ ok: true }));

// --- Create assignment (teacher only in that classroom) ---
app.post(
    "/classrooms/:classId/assignments",
    auth,
    loadUser,
    async (req, res) => {
        const classId = req.params.classId;
        const { title, description, due_at } = req.body || {};
        if (!title || !due_at)
            return res
                .status(400)
                .json({ error: "title and due_at required (ISO string)" });

        const role = await isMemberOf(classId, req.user.dbId);
        if (role !== "teacher")
            return res.status(403).json({ error: "Teacher only" });

        // simple due date parse; trust client to send ISO; database will validate timestamptz
        try {
            const { rows } = await pool.query(
                `INSERT INTO app.assignments (classroom_id, title, description, due_at, created_by)
       VALUES ($1,$2,$3,$4,$5)
       RETURNING id, classroom_id, title, description, due_at, created_by, created_at`,
                [classId, title, description || null, due_at, req.user.dbId]
            );
            res.status(201).json(rows[0]);
        } catch (e) {
            console.error(e);
            res.status(500).json({ error: "create failed" });
        }
    }
);

// --- List assignments for my classroom (must be a member) ---
app.get(
    "/classrooms/:classId/assignments",
    auth,
    loadUser,
    async (req, res) => {
        const classId = req.params.classId;
        const role = await isMemberOf(classId, req.user.dbId);
        if (!role) return res.status(403).json({ error: "Not a member" });

        const { rows } = await pool.query(
            `SELECT a.id, a.title, a.description, a.due_at, a.created_at
       FROM app.assignments a
      WHERE a.classroom_id=$1
      ORDER BY a.created_at DESC`,
            [classId]
        );
        res.json(rows);
    }
);

// --- Get assignment details (& attachments) if member ---
app.get("/assignments/:id", auth, loadUser, async (req, res) => {
    const aId = req.params.id;
    const { rows: ax } = await pool.query(
        "SELECT * FROM app.assignments WHERE id=$1",
        [aId]
    );
    if (!ax.length) return res.status(404).json({ error: "not found" });
    const assignment = ax[0];

    const role = await isMemberOf(assignment.classroom_id, req.user.dbId);
    if (!role) return res.status(403).json({ error: "Not a member" });

    const { rows: files } = await pool.query(
        "SELECT id, filename, size_bytes, etag FROM app.assignment_attachments WHERE assignment_id=$1",
        [aId]
    );
    assignment.attachments = files;
    res.json(assignment);
});

// --- Teacher: get presigned PUT to upload an attachment ---
app.post(
    "/assignments/:id/attachments/presign",
    auth,
    loadUser,
    async (req, res) => {
        const aId = req.params.id;
        const { filename, contentType } = req.body || {};
        if (!filename || !contentType)
            return res
                .status(400)
                .json({ error: "filename and contentType required" });

        // find assignment & ensure teacher in that classroom
        const { rows: ax } = await pool.query(
            "SELECT classroom_id FROM app.assignments WHERE id=$1",
            [aId]
        );
        if (!ax.length)
            return res.status(404).json({ error: "assignment not found" });
        const role = await isMemberOf(ax[0].classroom_id, req.user.dbId);
        if (role !== "teacher")
            return res.status(403).json({ error: "Teacher only" });

        if (!S3_BUCKET)
            return res.status(500).json({ error: "S3_BUCKET not configured" });

        const key = `${S3_PREFIX}/${
            ax[0].classroom_id
        }/assignments/${aId}/teacher/${Date.now()}_${safeName(filename)}`;
        try {
            const putCmd = new PutObjectCommand({
                Bucket: S3_BUCKET,
                Key: key,
                ContentType: contentType,
            });
            const url = await getSignedUrl(s3, putCmd, { expiresIn: 900 }); // 15 min
            res.json({
                url,
                method: "PUT",
                key,
                headers: { "Content-Type": contentType },
            });
        } catch (e) {
            console.error("presign failed:", e);
            res.status(500).json({ error: "presign failed" });
        }
    }
);

// --- Teacher: commit attachment metadata after upload ---
app.post(
    "/assignments/:id/attachments/commit",
    auth,
    loadUser,
    async (req, res) => {
        const aId = req.params.id;
        const { key, filename, size, etag } = req.body || {};
        if (!key || !filename)
            return res.status(400).json({ error: "key and filename required" });

        const { rows: ax } = await pool.query(
            "SELECT classroom_id FROM app.assignments WHERE id=$1",
            [aId]
        );
        if (!ax.length)
            return res.status(404).json({ error: "assignment not found" });
        const role = await isMemberOf(ax[0].classroom_id, req.user.dbId);
        if (role !== "teacher")
            return res.status(403).json({ error: "Teacher only" });

        try {
            const { rows } = await pool.query(
                `INSERT INTO app.assignment_attachments (assignment_id, s3_key, filename, size_bytes, etag)
       VALUES ($1,$2,$3,$4,$5)
       RETURNING id, filename, size_bytes, etag`,
                [aId, key, filename, size || null, etag || null]
            );
            res.status(201).json(rows[0]);
        } catch (e) {
            console.error(e);
            res.status(500).json({ error: "commit failed" });
        }
    }
);

// --- (optional) presign download for any member ---
app.post(
    "/assignments/:id/attachments/:attId/presign-download",
    auth,
    loadUser,
    async (req, res) => {
        const aId = req.params.id,
            attId = req.params.attId;
        const { rows: ax } = await pool.query(
            "SELECT classroom_id FROM app.assignments WHERE id=$1",
            [aId]
        );
        if (!ax.length)
            return res.status(404).json({ error: "assignment not found" });
        const role = await isMemberOf(ax[0].classroom_id, req.user.dbId);
        if (!role) return res.status(403).json({ error: "Not a member" });

        const { rows: fx } = await pool.query(
            "SELECT s3_key, filename FROM app.assignment_attachments WHERE id=$1 AND assignment_id=$2",
            [attId, aId]
        );
        if (!fx.length)
            return res.status(404).json({ error: "file not found" });

        const getCmd = new GetObjectCommand({
            Bucket: S3_BUCKET,
            Key: fx[0].s3_key,
        });
        const url = await getSignedUrl(s3, getCmd, { expiresIn: 900 });
        res.json({ url, filename: fx[0].filename });
    }
);

app.listen(+PORT, () => console.log(`assignment-service on :${PORT}`));
