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

// ----- env -----
const {
    PORT = "3003",
    DB_HOST,
    DB_PORT = "5432",
    DB_NAME = "postgres",
    DB_USER = "postgres",
    DB_PASSWORD,
    COGNITO_USER_POOL_ID,
    COGNITO_CLIENT_ID,
    S3_BUCKET,
    S3_REGION = process.env.AWS_REGION || "ap-south-1",
    S3_PREFIX = "classrooms",
} = process.env;

// ----- setup -----
const app = express();
app.use(
    cors({
        origin: "*",
        methods: ["GET", "POST", "OPTIONS"],
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

// utils
const UUID_RE =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const isUuid = (s) => UUID_RE.test(s);
const safeName = (name) =>
    (name || "file").replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 128);

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

async function assignmentContext(assignmentId) {
    // returns { classroom_id, due_at }
    const { rows } = await pool.query(
        "SELECT classroom_id, due_at FROM app.assignments WHERE id=$1",
        [assignmentId]
    );
    return rows[0] || null;
}

async function memberRole(classroomId, userId) {
    const { rows } = await pool.query(
        "SELECT role_in_class FROM app.memberships WHERE classroom_id=$1 AND user_id=$2",
        [classroomId, userId]
    );
    return rows[0]?.role_in_class || null;
}

app.get("/health", (_req, res) => res.json({ ok: true }));

// ---- Student: request presigned PUT (only if not already submitted) ----
app.post(
    "/assignments/:id/submissions/presign",
    auth,
    loadUser,
    async (req, res) => {
        const aId = req.params.id;
        const { filename, contentType } = req.body || {};
        if (!isUuid(aId))
            return res.status(400).json({ error: "invalid assignment id" });
        if (!filename || !contentType)
            return res
                .status(400)
                .json({ error: "filename and contentType required" });
        if (!S3_BUCKET)
            return res.status(500).json({ error: "S3_BUCKET not configured" });

        const a = await assignmentContext(aId);
        if (!a) return res.status(404).json({ error: "assignment not found" });

        const role = await memberRole(a.classroom_id, req.user.dbId);
        if (!role)
            return res.status(403).json({ error: "Not a classroom member" });

        // Has the student already submitted?
        const { rows: subx } = await pool.query(
            "SELECT id FROM app.submissions WHERE assignment_id=$1 AND user_id=$2",
            [aId, req.user.dbId]
        );
        if (subx.length)
            return res.status(409).json({ error: "already submitted" });

        const key = `${S3_PREFIX}/${
            a.classroom_id
        }/assignments/${aId}/submissions/${
            req.user.dbId
        }/${Date.now()}_${safeName(filename)}`;
        try {
            const putCmd = new PutObjectCommand({
                Bucket: S3_BUCKET,
                Key: key,
                ContentType: contentType,
            });
            const url = await getSignedUrl(s3, putCmd, { expiresIn: 900 });
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

// ---- Student: commit submission (first one wins; subsequent attempts 409) ----
app.post(
    "/assignments/:id/submissions/commit",
    auth,
    loadUser,
    async (req, res) => {
        const aId = req.params.id;
        const { key, filename, size, etag } = req.body || {};
        if (!isUuid(aId))
            return res.status(400).json({ error: "invalid assignment id" });
        if (!key || !filename)
            return res.status(400).json({ error: "key and filename required" });

        const a = await assignmentContext(aId);
        if (!a) return res.status(404).json({ error: "assignment not found" });

        const role = await memberRole(a.classroom_id, req.user.dbId);
        if (!role)
            return res.status(403).json({ error: "Not a classroom member" });

        try {
            const { rows } = await pool.query(
                `INSERT INTO app.submissions (assignment_id, user_id, s3_key, filename, size_bytes, etag)
       VALUES ($1,$2,$3,$4,$5,$6)
       ON CONFLICT (assignment_id, user_id) DO NOTHING
       RETURNING id, filename, size_bytes, submitted_at`,
                [aId, req.user.dbId, key, filename, size || null, etag || null]
            );
            if (!rows.length)
                return res.status(409).json({ error: "already submitted" });
            res.status(201).json(rows[0]);
        } catch (e) {
            console.error(e);
            res.status(500).json({ error: "commit failed" });
        }
    }
);

// ---- Student: get my submission (if any) ----
app.get("/assignments/:id/submissions/me", auth, loadUser, async (req, res) => {
    const aId = req.params.id;
    if (!isUuid(aId))
        return res.status(400).json({ error: "invalid assignment id" });

    const a = await assignmentContext(aId);
    if (!a) return res.status(404).json({ error: "assignment not found" });

    const role = await memberRole(a.classroom_id, req.user.dbId);
    if (!role) return res.status(403).json({ error: "Not a classroom member" });

    const { rows } = await pool.query(
        `SELECT id, filename, size_bytes, etag, submitted_at
       FROM app.submissions WHERE assignment_id=$1 AND user_id=$2`,
        [aId, req.user.dbId]
    );
    if (!rows.length) return res.json(null);
    res.json(rows[0]);
});

// ---- Teacher: list all submissions for an assignment ----
app.get("/assignments/:id/submissions", auth, loadUser, async (req, res) => {
    const aId = req.params.id;
    if (!isUuid(aId))
        return res.status(400).json({ error: "invalid assignment id" });

    const a = await assignmentContext(aId);
    if (!a) return res.status(404).json({ error: "assignment not found" });

    const role = await memberRole(a.classroom_id, req.user.dbId);
    if (role !== "teacher")
        return res.status(403).json({ error: "Teacher only" });

    const { rows } = await pool.query(
        `SELECT s.id, u.name, u.email, s.filename, s.size_bytes, s.submitted_at
       FROM app.submissions s
       JOIN app.users u ON u.id = s.user_id
      WHERE s.assignment_id=$1
      ORDER BY s.submitted_at DESC`,
        [aId]
    );
    res.json(rows);
});

// ---- Teacher or owner student: presign download ----
app.post(
    "/assignments/:id/submissions/:subId/presign-download",
    auth,
    loadUser,
    async (req, res) => {
        const aId = req.params.id,
            subId = req.params.subId;
        if (!isUuid(aId) || !isUuid(subId))
            return res.status(400).json({ error: "invalid id" });

        const { rows: sx } = await pool.query(
            `SELECT s.s3_key, s.filename, s.user_id, a.classroom_id
       FROM app.submissions s
       JOIN app.assignments a ON a.id = s.assignment_id
      WHERE s.id=$1 AND s.assignment_id=$2`,
            [subId, aId]
        );
        if (!sx.length)
            return res.status(404).json({ error: "submission not found" });

        const role = await memberRole(sx[0].classroom_id, req.user.dbId);
        if (!role)
            return res.status(403).json({ error: "Not a classroom member" });
        const isOwner = sx[0].user_id === req.user.dbId;
        if (!(isOwner || role === "teacher"))
            return res.status(403).json({ error: "Forbidden" });

        const getCmd = new GetObjectCommand({
            Bucket: S3_BUCKET,
            Key: sx[0].s3_key,
        });
        const url = await getSignedUrl(s3, getCmd, { expiresIn: 900 });
        res.json({ url, filename: sx[0].filename });
    }
);

app.listen(+PORT, () => console.log(`submission-service on :${PORT}`));
