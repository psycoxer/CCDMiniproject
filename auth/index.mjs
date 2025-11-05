// Simplest possible: on PostConfirmation, upsert into app.users
import { Pool } from "pg";

const pool = new Pool({
    host: process.env.DB_HOST, // RDS endpoint or RDS Proxy
    port: +(process.env.DB_PORT || 5432),
    user: process.env.DB_USER || "postgres",
    password: process.env.DB_PASSWORD, // plain env for simplicity
    database: process.env.DB_NAME || "postgres",
    ssl:
        process.env.REQUIRE_SSL === "false"
            ? false
            : { rejectUnauthorized: false },
    max: 2,
    idleTimeoutMillis: 30000,
});

export const handler = async (event) => {
    // Only handle PostConfirmation
    if (event?.triggerSource !== "PostConfirmation_ConfirmSignUp") return event;

    const attrs = event.request?.userAttributes || {};
    const sub = attrs.sub || event.userName; // Cognito sub
    const email = attrs.email || null;
    const name =
        attrs.name ||
        [attrs.given_name, attrs.family_name].filter(Boolean).join(" ") ||
        null;

    if (!sub) return event; // don't block signup if something is missing

    const sql = `
    INSERT INTO app.users (cognito_sub, email, name)
    VALUES ($1, $2, $3)
    ON CONFLICT (cognito_sub) DO UPDATE
      SET email = EXCLUDED.email,
          name  = COALESCE(EXCLUDED.name, app.users.name)
  `;

    const client = await pool.connect();
    try {
        await client.query(sql, [sub, email, name]);
    } catch (e) {
        // Keep signup flow resilient—log and return
        console.error("PostConfirmation upsert failed:", e?.message || e);
    } finally {
        client.release();
    }

    return event; // always return event to Cognito
};
