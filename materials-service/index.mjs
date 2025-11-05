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
    PORT = "3004",
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

// ---- setup ----
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

// ---- helpers ----
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
        const p = await verifier.verify(token);
        req.user = { sub: p.sub, email: p.email || null };
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

async function memberRole(classroomId, userId) {
    const { rows } = await pool.query(
        "SELECT role_in_class FROM app.memberships WHERE classroom_id=$1 AND user_id=$2",
        [classroomId, userId]
    );
    return rows[0]?.role_in_class || null;
}

// ---- routes ----
app.get("/health", (_req, res) => res.json({ ok: true }));

// Teacher: presign upload
app.post(
    "/classrooms/:classId/materials/presign",
    auth,
    loadUser,
    async (req, res) => {
        const classId = req.params.classId;
        const { filename, contentType } = req.body || {};
        if (!isUuid(classId))
            return res.status(400).json({ error: "invalid classroom id" });
        if (!filename || !contentType)
            return res
                .status(400)
                .json({ error: "filename and contentType required" });
        if (!S3_BUCKET)
            return res.status(500).json({ error: "S3_BUCKET not configured" });

        const role = await memberRole(classId, req.user.dbId);
        if (role !== "teacher")
            return res.status(403).json({ error: "Teacher only" });

        const key = `${S3_PREFIX}/${classId}/materials/${Date.now()}_${safeName(
            filename
        )}`;
        try {
            const putCmd = new PutObjectCommand({
                Bucket: S3_BUCKET,
                Key: key,
                ContentType: contentType,
            });
            const url = await getSignedUrl(s3, putCmd, { expiresIn: 900 }); // 15m
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

// Teacher: commit metadata
app.post(
    "/classrooms/:classId/materials/commit",
    auth,
    loadUser,
    async (req, res) => {
        const classId = req.params.classId;
        const { key, filename, size, etag } = req.body || {};
        if (!isUuid(classId))
            return res.status(400).json({ error: "invalid classroom id" });
        if (!key || !filename)
            return res.status(400).json({ error: "key and filename required" });

        const role = await memberRole(classId, req.user.dbId);
        if (role !== "teacher")
            return res.status(403).json({ error: "Teacher only" });

        try {
            const { rows } = await pool.query(
                `INSERT INTO app.materials (classroom_id, uploaded_by, s3_key, filename, size_bytes, etag)
       VALUES ($1,$2,$3,$4,$5,$6)
       RETURNING id, filename, size_bytes, uploaded_at`,
                [
                    classId,
                    req.user.dbId,
                    key,
                    filename,
                    size || null,
                    etag || null,
                ]
            );
            res.status(201).json(rows[0]);
        } catch (e) {
            console.error(e);
            res.status(500).json({ error: "commit failed" });
        }
    }
);

// Member: list materials
app.get("/classrooms/:classId/materials", auth, loadUser, async (req, res) => {
    const classId = req.params.classId;
    if (!isUuid(classId))
        return res.status(400).json({ error: "invalid classroom id" });

    const role = await memberRole(classId, req.user.dbId);
    if (!role) return res.status(403).json({ error: "Not a classroom member" });

    const { rows } = await pool.query(
        `SELECT m.id, m.filename, m.size_bytes, m.uploaded_at, u.name AS uploaded_by_name, u.email AS uploaded_by_email
       FROM app.materials m
       JOIN app.users u ON u.id = m.uploaded_by
      WHERE m.classroom_id=$1
      ORDER BY m.uploaded_at DESC`,
        [classId]
    );
    res.json(rows);
});

// Member: get presigned download
app.post(
    "/materials/:id/presign-download",
    auth,
    loadUser,
    async (req, res) => {
        const id = req.params.id;
        if (!isUuid(id)) return res.status(400).json({ error: "invalid id" });

        const { rows } = await pool.query(
            `SELECT m.s3_key, m.filename, m.classroom_id
       FROM app.materials m
      WHERE m.id=$1`,
            [id]
        );
        if (!rows.length) return res.status(404).json({ error: "not found" });

        const role = await memberRole(rows[0].classroom_id, req.user.dbId);
        if (!role)
            return res.status(403).json({ error: "Not a classroom member" });

        const getCmd = new GetObjectCommand({
            Bucket: S3_BUCKET,
            Key: rows[0].s3_key,
        });
        const url = await getSignedUrl(s3, getCmd, { expiresIn: 900 });
        res.json({ url, filename: rows[0].filename });
    }
);

app.listen(+PORT, () => console.log(`materials-service on :${PORT}`));
