import express from "express";
import cors from "cors";
import { Pool } from "pg";
import { CognitoJwtVerifier } from "aws-jwt-verify";

// -------- env --------
const {
    PORT = "3001",
    DB_HOST,
    DB_PORT = "5432",
    DB_NAME = "postgres",
    DB_USER = "postgres",
    DB_PASSWORD,
    COGNITO_USER_POOL_ID,
    COGNITO_CLIENT_ID,
} = process.env;

// -------- db --------
const pool = new Pool({
    host: DB_HOST,
    port: +DB_PORT,
    database: DB_NAME,
    user: DB_USER,
    password: DB_PASSWORD,
    ssl: { rejectUnauthorized: false },
    max: 8,
});

// -------- auth (accept access tokens from your pool) --------
if (!COGNITO_USER_POOL_ID) {
    console.error("COGNITO_USER_POOL_ID env required");
    process.exit(1);
}
// const verifier = CognitoJwtVerifier.create({
//     userPoolId: COGNITO_USER_POOL_ID,
//     tokenUse: "access",
// });

const verifier = CognitoJwtVerifier.create({
    userPoolId: COGNITO_USER_POOL_ID,
    tokenUse: "access",
    clientId: COGNITO_CLIENT_ID || undefined,
    // allow a minute of local clock skew
    customJwtCheck: ({ payload }) => {
        const now = Math.floor(Date.now() / 1000);
        if (payload.nbf && now + 60 < payload.nbf)
            throw new Error("token not yet valid");
    },
});

// async function auth(req, res, next) {
//     const hdr = req.headers.authorization || "";
//     const token = hdr.startsWith("Bearer ") ? hdr.slice(7) : null;
//     if (!token)
//         return res
//             .status(401)
//             .json({ error: "Missing Authorization: Bearer <token>" });
//     try {
//         const payload = await verifier.verify(token);
//         req.user = { sub: payload.sub, email: payload.email || null };
//         next();
//     } catch (e) {
//         return res.status(401).json({ error: "Invalid token" });
//     }
// }

async function auth(req, res, next) {
    const hdr = req.headers.authorization || "";
    const token = hdr.startsWith("Bearer ") ? hdr.slice(7) : null;
    if (!token)
        return res
            .status(401)
            .json({ error: "Missing Authorization: Bearer <token>" });
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
    // Map Cognito sub -> app.users row
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

// -------- helpers --------
const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
function genCode(len = 6) {
    let s = "";
    for (let i = 0; i < len; i++)
        s += ALPHABET[Math.floor(Math.random() * ALPHABET.length)];
    return s;
}

// -------- app --------
const app = express();

// CORS: wide-open (no cookies). Allows Authorization header.
app.use(
    cors({
        origin: "*",
        methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization"],
    })
);
app.use(express.json());
app.get("/health", (_req, res) => res.json({ ok: true }));

// Create classroom (teacher only)
app.post("/classrooms", auth, loadUser, async (req, res) => {
    if (req.user.role !== "teacher")
        return res.status(403).json({ error: "Teacher only" });
    const { name, section } = req.body || {};
    if (!name) return res.status(400).json({ error: "name required" });

    // generate unique code with a few retries
    let code, created;
    for (let i = 0; i < 5; i++) {
        code = genCode(6);
        try {
            const { rows } = await pool.query(
                `INSERT INTO app.classrooms (owner_user_id, name, section, code)
         VALUES ($1,$2,$3,$4)
         RETURNING id, name, section, code, invite_token, created_at`,
                [req.user.dbId, name, section || null, code]
            );
            created = rows[0];
            break;
        } catch (e) {
            if (e.code === "23505") continue; // unique violation on code -> retry
            console.error(e);
            return res.status(500).json({ error: "create failed" });
        }
    }
    if (!created)
        return res
            .status(500)
            .json({ error: "could not generate unique code" });

    // add creator as teacher member
    await pool.query(
        `INSERT INTO app.memberships (user_id, classroom_id, role_in_class)
     VALUES ($1,$2,'teacher') ON CONFLICT DO NOTHING`,
        [req.user.dbId, created.id]
    );

    res.status(201).json(created);
});

// List my classrooms
app.get("/classrooms", auth, loadUser, async (req, res) => {
    const { rows } = await pool.query(
        `SELECT c.id, c.name, c.section, c.code, c.invite_token, c.created_at,
            m.role_in_class
       FROM app.classrooms c
       JOIN app.memberships m ON m.classroom_id = c.id
      WHERE m.user_id = $1
      ORDER BY c.created_at DESC`,
        [req.user.dbId]
    );
    res.json(rows);
});

// GET /classrooms/me  -> { id, email, name, role }
app.get("/classrooms/me", auth, loadUser, async (req, res) => {
    const { rows } = await pool.query(
        "SELECT id, name, email, role FROM app.users WHERE id=$1",
        [req.user.dbId]
    );
    if (!rows.length) return res.status(404).json({ error: "User not found" });
    res.json(rows[0]);
});

// Get classroom (must be a member)
app.get("/classrooms/:id", auth, loadUser, async (req, res) => {
    const { rows } = await pool.query(
        `SELECT c.id, c.name, c.section, c.code, c.invite_token, c.created_at,
            m.role_in_class
       FROM app.classrooms c
       JOIN app.memberships m ON m.classroom_id = c.id
      WHERE c.id = $1 AND m.user_id = $2`,
        [req.params.id, req.user.dbId]
    );
    if (!rows.length) return res.status(404).json({ error: "not found" });
    res.json(rows[0]);
});

// Join by code (student/any user)
app.post("/classrooms/:id/join", auth, loadUser, async (req, res) => {
    const { code } = req.body || {};
    if (!code) return res.status(400).json({ error: "code required" });

    const { rows: cr } = await pool.query(
        "SELECT id, code FROM app.classrooms WHERE id=$1",
        [req.params.id]
    );
    if (!cr.length)
        return res.status(404).json({ error: "classroom not found" });
    if (cr[0].code !== code)
        return res.status(400).json({ error: "invalid code" });

    await pool.query(
        `INSERT INTO app.memberships (user_id, classroom_id, role_in_class)
     VALUES ($1,$2,'student') ON CONFLICT DO NOTHING`,
        [req.user.dbId, req.params.id]
    );
    res.json({ joined: true, classroom_id: req.params.id });
});

// Join by invite link token (no classroom id needed)
// app.post("/join/:token", auth, loadUser, async (req, res) => {
//     const { rows: cr } = await pool.query(
//         "SELECT id FROM app.classrooms WHERE invite_token::text = $1",
//         [req.params.token]
//     );
//     if (!cr.length) return res.status(404).json({ error: "invalid token" });

//     await pool.query(
//         `INSERT INTO app.memberships (user_id, classroom_id, role_in_class)
//      VALUES ($1,$2,'student') ON CONFLICT DO NOTHING`,
//         [req.user.dbId, cr[0].id]
//     );
//     res.json({ joined: true, classroom_id: cr[0].id });
// });

// Join by invite link token (support both paths)
app.post(
    ["/join/:token", "/classrooms/join/:token"],
    auth,
    loadUser,
    async (req, res) => {
        const token = req.params.token;
        if (!token) return res.status(400).json({ error: "token required" });

        const { rows: cr } = await pool.query(
            "SELECT id FROM app.classrooms WHERE invite_token::text = $1",
            [token]
        );
        if (!cr.length)
            return res.status(404).json({ error: "invalid invite" });

        await pool.query(
            `INSERT INTO app.memberships (user_id, classroom_id, role_in_class)
     VALUES ($1,$2,'student') ON CONFLICT DO NOTHING`,
            [req.user.dbId, cr[0].id]
        );
        res.json({ joined: true, classroom_id: cr[0].id });
    }
);

// List members (must be a member)
app.get("/classrooms/:id/members", auth, loadUser, async (req, res) => {
    const { rows } = await pool.query(
        `SELECT u.id as user_id, u.name, u.email, m.role_in_class, m.joined_at
       FROM app.memberships m
       JOIN app.users u ON u.id = m.user_id
      WHERE m.classroom_id = $1
      ORDER BY m.role_in_class DESC, u.name NULLS LAST`,
        [req.params.id]
    );
    res.json(rows);
});

app.listen(+PORT, () => console.log(`classroom-service on :${PORT}`));
