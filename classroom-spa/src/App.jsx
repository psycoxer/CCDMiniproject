// App.jsx — Full single-file React SPA for your AWS Classroom project
// Features:
// - Cognito Hosted UI login with PKCE (no client secret), robust against double-invocation
// - Role awareness via GET /classrooms/me
// - Teacher: create classrooms, create assignments, upload assignment attachments, view/download submissions
// - Student: join classroom (by code or invite link), view assignments, upload single submission
// - Materials: teacher upload, members list & download
// - Works with your ALB path rules: /classrooms*, /assignments*, /submissions*, /materials*
//
// HOW TO USE (local dev):
// 1) Vite scaffold:  npm create vite@latest classroom-spa -- --template react
// 2) Replace src/App.jsx with this file. Keep src/main.jsx default (you may remove React.StrictMode for dev).
// 3) npm i  → npm run dev  → http://localhost:5173
// 4) Cognito App Client settings (Public client, no secret):
//    - Authorization code grant ON; Implicit OFF
//    - Scopes: openid, email, phone
//    - Callback URLs:  http://localhost:5173/callback , http://127.0.0.1:5173/callback
//    - Sign-out URLs:  http://localhost:5173/ , http://127.0.0.1:5173/
//
// If invite-link join hits 404 through ALB, add an ALB rule mapping "/join*" -> classroom TG
// (UI automatically falls back to /join/:token if /classrooms/join/:token returns 404.)

import React, { useEffect, useMemo, useRef, useState } from "react";

// ====== CONFIG ======
const COGNITO_DOMAIN =
    "https://ap-south-1lnswxhxim.auth.ap-south-1.amazoncognito.com";
const COGNITO_CLIENT_ID = "2vu8t06k47ad11ud3tepue8jna"; // public client (no secret)
const REDIRECT_URI = `${window.location.origin}/callback`;
const LOGOUT_URI = `${window.location.origin}/`;

// Your ALB (HTTP for now; switch to HTTPS + custom domain later)
// const API_BASE = "http://SeriveLB-1593805698.ap-south-1.elb.amazonaws.com";
const API_BASE = "https://d33ozn9tb26io5.cloudfront.net";

// ====== PKCE HELPERS ======
const b64url = (buf) => {
    const str = btoa(String.fromCharCode.apply(null, new Uint8Array(buf)));
    return str.replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
};
const randStr = (len = 64) => {
    const arr = new Uint8Array(len);
    crypto.getRandomValues(arr);
    return Array.from(arr)
        .map((x) => ("0" + x.toString(16)).slice(-2))
        .join("");
};
async function sha256(input) {
    const data = new TextEncoder().encode(input);
    const hash = await crypto.subtle.digest("SHA-256", data);
    return b64url(hash);
}
function saveSession(obj) {
    sessionStorage.setItem("auth", JSON.stringify(obj));
    localStorage.setItem("auth", JSON.stringify(obj));
}
function loadSession() {
    try {
        return JSON.parse(
            sessionStorage.getItem("auth") ||
                localStorage.getItem("auth") ||
                "{}"
        );
    } catch {
        return {};
    }
}
function clearSession() {
    sessionStorage.removeItem("auth");
    localStorage.removeItem("auth");
}
function parseJwt(token) {
    try {
        const [, b] = token.split(".");
        const json = atob(b.replaceAll("-", "+").replaceAll("_", "/"));
        return JSON.parse(decodeURIComponent(escape(json)));
    } catch {
        return {};
    }
}

function setPKCE(verifier, state) {
    sessionStorage.setItem("pkce_verifier", verifier);
    localStorage.setItem("pkce_verifier", verifier);
    sessionStorage.setItem("pkce_state", state);
    localStorage.setItem("pkce_state", state);
    sessionStorage.setItem("redirect_uri", REDIRECT_URI);
    localStorage.setItem("redirect_uri", REDIRECT_URI);
}
function getPKCE() {
    return {
        verifier:
            sessionStorage.getItem("pkce_verifier") ||
            localStorage.getItem("pkce_verifier"),
        state:
            sessionStorage.getItem("pkce_state") ||
            localStorage.getItem("pkce_state"),
        redirect:
            sessionStorage.getItem("redirect_uri") ||
            localStorage.getItem("redirect_uri") ||
            REDIRECT_URI,
    };
}
function clearPKCE() {
    ["pkce_verifier", "pkce_state", "redirect_uri"].forEach((k) => {
        sessionStorage.removeItem(k);
        localStorage.removeItem(k);
    });
}

function login() {
    const verifier = randStr(64);
    const state = randStr(24);
    setPKCE(verifier, state);
    sha256(verifier).then((challenge) => {
        const url = new URL(`${COGNITO_DOMAIN}/oauth2/authorize`);
        url.searchParams.set("client_id", COGNITO_CLIENT_ID);
        url.searchParams.set("response_type", "code");
        url.searchParams.set("scope", "openid email phone");
        url.searchParams.set("redirect_uri", REDIRECT_URI);
        url.searchParams.set("code_challenge_method", "S256");
        url.searchParams.set("code_challenge", challenge);
        url.searchParams.set("state", state);
        window.location = url.toString();
    });
}

async function exchangeCodeForTokens(code, state) {
    const { verifier, state: savedState, redirect } = getPKCE();
    if (!verifier) throw new Error("Missing code_verifier");
    if (savedState && state && savedState !== state)
        throw new Error("State mismatch");
    const body = new URLSearchParams();
    body.set("grant_type", "authorization_code");
    body.set("client_id", COGNITO_CLIENT_ID);
    body.set("code", code);
    body.set("redirect_uri", redirect);
    body.set("code_verifier", verifier);
    const r = await fetch(`${COGNITO_DOMAIN}/oauth2/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body,
    });
    if (!r.ok) {
        throw new Error(`Token exchange failed: ${r.status} ${await r.text()}`);
    }
    const tok = await r.json();
    const id = parseJwt(tok.id_token);
    clearPKCE();
    const full = { ...tok, id };
    saveSession(full);
    return full;
}

function logout() {
    clearSession();
    clearPKCE();
    const url = new URL(`${COGNITO_DOMAIN}/logout`);
    url.searchParams.set("client_id", COGNITO_CLIENT_ID);
    url.searchParams.set("logout_uri", LOGOUT_URI);
    window.location = url.toString();
}

// ====== API HELPERS ======
async function apiGet(path, token) {
    const r = await fetch(`${API_BASE}${path}`, {
        headers: { Authorization: `Bearer ${token}` },
    });
    if (!r.ok) throw new Error(`${r.status}: ${await r.text()}`);
    return r.json();
}
async function apiPost(path, token, body) {
    const r = await fetch(`${API_BASE}${path}`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(body || {}),
    });
    if (!r.ok) throw new Error(`${r.status}: ${await r.text()}`);
    return r.json?.() ?? null;
}

// Upload to S3 via presigned URL
async function putPresigned(url, file, contentType) {
    const r = await fetch(url, {
        method: "PUT",
        headers: { "Content-Type": contentType || "application/octet-stream" },
        body: file,
    });
    if (!r.ok) throw new Error(`S3 PUT failed: ${r.status}`);
    // ETag is in header sometimes; not required by your backend
    return r;
}

// ====== APP ======
export default function App() {
    const [auth, setAuth] = useState(loadSession());
    const [me, setMe] = useState(null);
    const [classes, setClasses] = useState([]);
    const [selected, setSelected] = useState(null); // selected classroom
    const [loading, setLoading] = useState(false);
    const didHandleCallback = useRef(false);
    const isAuthed = !!auth?.access_token;
    const role = me?.role || "student";

    // Handle /callback safely once (StrictMode-safe)
    useEffect(() => {
        const u = new URL(window.location.href);
        if (u.pathname !== "/callback") return;
        if (didHandleCallback.current) return;
        didHandleCallback.current = true;

        const code = u.searchParams.get("code");
        const state = u.searchParams.get("state");
        // Clean URL *before* async work to avoid double-run
        window.history.replaceState({}, "", "/");
        (async () => {
            try {
                const a = await exchangeCodeForTokens(code, state);
                setAuth(a);
            } catch (e) {
                const msg = String(e);
                if (!msg.includes("invalid_grant")) alert(msg); // ignore second-use noise
            }
        })();
    }, []);

    // Load profile & classes when authed
    useEffect(() => {
        if (!isAuthed) return;
        let gone = false;
        (async () => {
            try {
                setLoading(true);
                const meRes = await apiGet("/classrooms/me", auth.access_token);
                if (gone) return;
                setMe(meRes);
                const list = await apiGet("/classrooms", auth.access_token);
                if (gone) return;
                setClasses(list);
            } catch (e) {
                console.error(e);
                alert("API error: " + e.message);
            } finally {
                if (!gone) setLoading(false);
            }
        })();
        return () => {
            gone = true;
        };
    }, [isAuthed]);

    return (
        <div style={S.page}>
            <Header
                isAuthed={isAuthed}
                me={me}
                onLogin={login}
                onLogout={logout}
            />

            {!isAuthed ? (
                <Center>
                    <h1 style={S.h1}>Classroom — Lite</h1>
                    <p style={S.muted}>Sign in with Cognito to continue.</p>
                    <button style={S.primary} onClick={login}>
                        Sign in
                    </button>
                    <Card>
                        <p>
                            <b>Callback:</b> {REDIRECT_URI}
                        </p>
                        <p style={S.muted}>
                            Ensure this is added in Cognito Allowed Callback
                            URLs.
                        </p>
                    </Card>
                </Center>
            ) : (
                <div style={S.container}>
                    <div style={S.layout}>
                        <Card>
                            <div style={S.flexBetween}>
                                <h2 style={S.h2}>My Classrooms</h2>
                                {role === "teacher" && (
                                    <CreateClass
                                        token={auth.access_token}
                                        onCreated={(c) => {
                                            setClasses([c, ...classes]);
                                        }}
                                    />
                                )}
                            </div>
                            {loading ? (
                                <p>Loading…</p>
                            ) : classes.length ? (
                                <ul style={S.list}>
                                    {classes.map((c) => (
                                        <li
                                            key={c.id}
                                            style={S.listItem}
                                            onClick={() => setSelected(c)}
                                        >
                                            <div>
                                                <div style={S.title}>
                                                    {c.name}{" "}
                                                    <span style={S.badge}>
                                                        Sec {c.section || "-"}
                                                    </span>
                                                </div>
                                                <div style={S.subtle}>
                                                    Code: {c.code} •{" "}
                                                    {new Date(
                                                        c.created_at ||
                                                            Date.now()
                                                    ).toLocaleString()}
                                                </div>
                                            </div>
                                            <div
                                                style={{
                                                    display: "grid",
                                                    gap: 6,
                                                    justifyItems: "end",
                                                }}
                                            >
                                                {c.invite_token &&
                                                    role === "teacher" && (
                                                        <Copyable
                                                            label="Invite"
                                                            value={`JOIN TOKEN: ${c.invite_token}`}
                                                        />
                                                    )}
                                            </div>
                                        </li>
                                    ))}
                                </ul>
                            ) : (
                                <p style={S.muted}>No classrooms yet.</p>
                            )}
                        </Card>

                        <div style={{ display: "grid", gap: 16 }}>
                            {role !== "teacher" && (
                                <JoinPanel
                                    token={auth.access_token}
                                    onJoined={async () => {
                                        const list = await apiGet(
                                            "/classrooms",
                                            auth.access_token
                                        );
                                        setClasses(list);
                                    }}
                                />
                            )}
                            <Profile me={me} auth={auth} />
                        </div>
                    </div>

                    {selected && (
                        <ClassroomDetail
                            key={selected.id}
                            token={auth.access_token}
                            me={me}
                            cls={selected}
                            onClose={() => setSelected(null)}
                        />
                    )}
                </div>
            )}
        </div>
    );
}

// ====== HEADER & COMMON ======
function Header({ isAuthed, me, onLogin, onLogout }) {
    return (
        <div style={S.header}>
            <div style={S.brand}>
                Classroom<span style={{ opacity: 0.7 }}>Lite</span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                {isAuthed && (
                    <div style={S.avatar}>
                        {(me?.name || me?.email || "U")
                            .slice(0, 1)
                            .toUpperCase()}
                    </div>
                )}
                {!isAuthed ? (
                    <button style={S.ghost} onClick={onLogin}>
                        Sign in
                    </button>
                ) : (
                    <button style={S.ghost} onClick={onLogout}>
                        Sign out
                    </button>
                )}
            </div>
        </div>
    );
}

function Card({ children }) {
    return <div style={S.card}>{children}</div>;
}
function Center({ children }) {
    return <div style={S.center}>{children}</div>;
}
function Row({ label, value, mono }) {
    return (
        <div
            style={{
                display: "flex",
                justifyContent: "space-between",
                gap: 16,
            }}
        >
            <div style={S.muted}>{label}</div>
            <div
                style={{
                    fontFamily: mono
                        ? "ui-monospace, SFMono-Regular, Menlo, monospace"
                        : "inherit",
                }}
            >
                {String(value ?? "")}
            </div>
        </div>
    );
}
function Copyable({ label, value }) {
    const [copied, setCopied] = useState(false);
    return (
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={S.subtle}>{label}:</span>
            <code style={S.code}>{value}</code>
            <button
                style={S.pill}
                onClick={() => {
                    navigator.clipboard.writeText(value);
                    setCopied(true);
                    setTimeout(() => setCopied(false), 1200);
                }}
            >
                {copied ? "Copied!" : "Copy"}
            </button>
        </div>
    );
}

// ====== LEFT PANE ======
function CreateClass({ token, onCreated }) {
    const [name, setName] = useState("Cloud 101");
    const [section, setSection] = useState("A");
    const [busy, setBusy] = useState(false);
    async function create() {
        setBusy(true);
        try {
            const c = await apiPost("/classrooms", token, { name, section });
            onCreated?.(c);
        } catch (e) {
            alert(e.message);
        } finally {
            setBusy(false);
        }
    }
    return (
        <button style={S.primary} disabled={busy} onClick={create}>
            {busy ? "Creating…" : "Create class"}
        </button>
    );
}

function JoinPanel({ token, onJoined }) {
    const [classId, setClassId] = useState("");
    const [code, setCode] = useState("");
    const [joinUrl, setJoinUrl] = useState("");
    async function byCode(e) {
        e.preventDefault();
        if (!classId || !code) return alert("Enter classId and code");
        try {
            await apiPost(`/classrooms/${classId}/join`, token, { code });
            alert("Joined!");
            onJoined?.();
        } catch (e) {
            alert(e.message);
        }
    }
    async function byLink(e) {
        e.preventDefault();
        if (!joinUrl) return;
        try {
            const tokenPart = (joinUrl.split("/").pop() || "").trim();
            if (!tokenPart) return alert("Paste a valid invite token or link");
            // Try the path that routes via ALB rule first; fallback to backend's /join/:token
            try {
                await apiPost(`/classrooms/join/${tokenPart}`, token);
            } catch (err) {
                const msg = String(err);
                if (msg.startsWith("404:")) {
                    await apiPost(`/join/${tokenPart}`, token);
                } else {
                    throw err;
                }
            }
            alert("Joined via invite!");
            onJoined?.();
        } catch (e) {
            alert(e.message);
        }
    }
    return (
        <Card>
            <h3 style={S.h3}>Join classroom (Student)</h3>
            <form onSubmit={byCode} style={S.formRow}>
                <input
                    style={S.input}
                    placeholder="Classroom ID (UUID)"
                    value={classId}
                    onChange={(e) => setClassId(e.target.value)}
                />
                <input
                    style={S.input}
                    placeholder="Join code"
                    value={code}
                    onChange={(e) => setCode(e.target.value)}
                />
                <button style={S.primary}>Join</button>
            </form>
            <div style={S.hr} />
            <form onSubmit={byLink} style={S.formRow}>
                <input
                    style={S.input}
                    placeholder="Paste invite token or link"
                    value={joinUrl}
                    onChange={(e) => setJoinUrl(e.target.value)}
                />
                <button style={S.secondary}>Use link</button>
            </form>
        </Card>
    );
}

function Profile({ me, auth }) {
    return (
        <Card>
            <h3 style={S.h3}>Profile</h3>
            <div style={{ display: "grid", gap: 6 }}>
                <Row label="Role" value={me?.role || "student"} />
                <Row label="Name" value={me?.name || "-"} />
                <Row
                    label="Email"
                    value={me?.email || auth?.id?.email || "-"}
                />
                <Row label="Sub (Cognito)" value={auth?.id?.sub || "-"} mono />
            </div>
        </Card>
    );
}

// ====== CLASSROOM DETAIL ======
function ClassroomDetail({ token, me, cls, onClose }) {
    const [tab, setTab] = useState("assignments");
    return (
        <Card>
            <div style={S.flexBetween}>
                <div>
                    <h2 style={S.h2}>
                        {cls.name}{" "}
                        <span style={S.badge}>Sec {cls.section || "-"}</span>
                    </h2>
                    <div style={S.subtle}>Code: {cls.code}</div>
                </div>
                <button style={S.pill} onClick={onClose}>
                    Close
                </button>
            </div>
            <div style={S.tabs}>
                <TabBtn
                    active={tab === "assignments"}
                    onClick={() => setTab("assignments")}
                >
                    Assignments
                </TabBtn>
                <TabBtn
                    active={tab === "materials"}
                    onClick={() => setTab("materials")}
                >
                    Materials
                </TabBtn>
                <TabBtn
                    active={tab === "members"}
                    onClick={() => setTab("members")}
                >
                    Members
                </TabBtn>
            </div>
            {tab === "assignments" && (
                <AssignmentsTab token={token} me={me} cls={cls} />
            )}
            {tab === "materials" && (
                <MaterialsTab token={token} me={me} cls={cls} />
            )}
            {tab === "members" && <MembersTab token={token} cls={cls} />}
        </Card>
    );
}
function TabBtn({ active, children, ...rest }) {
    return (
        <button
            style={{ ...S.tabBtn, ...(active ? S.tabBtnActive : {}) }}
            {...rest}
        >
            {children}
        </button>
    );
}

// ====== ASSIGNMENTS ======
function AssignmentsTab({ token, me, cls }) {
    const [list, setList] = useState([]);
    const [sel, setSel] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        let gone = false;
        (async () => {
            try {
                setLoading(true);
                const r = await apiGet(
                    `/classrooms/${cls.id}/assignments`,
                    token
                );
                if (!gone) {
                    setList(r);
                    setSel(r[0] || null);
                }
            } catch (e) {
                alert(e.message);
            } finally {
                if (!gone) setLoading(false);
            }
        })();
        return () => {
            gone = true;
        };
    }, [cls.id]);

    return (
        <div style={S.grid2}>
            <div>
                {me.role === "teacher" && (
                    <CreateAssignment
                        token={token}
                        classId={cls.id}
                        onCreated={(a) => {
                            setList([a, ...list]);
                            setSel(a);
                        }}
                    />
                )}
                {loading ? (
                    <p>Loading…</p>
                ) : list.length ? (
                    <ul style={S.list}>
                        {list.map((a) => (
                            <li
                                key={a.id}
                                style={S.listItem}
                                onClick={() => setSel(a)}
                            >
                                <div>
                                    <div style={S.title}>{a.title}</div>
                                    <div style={S.subtle}>
                                        Due:{" "}
                                        {new Date(a.due_at).toLocaleString()}
                                    </div>
                                </div>
                            </li>
                        ))}
                    </ul>
                ) : (
                    <p style={S.muted}>No assignments.</p>
                )}
            </div>
            <div>
                {sel ? (
                    <AssignmentDetail
                        token={token}
                        me={me}
                        assignmentId={sel.id}
                    />
                ) : (
                    <p style={S.muted}>Select an assignment</p>
                )}
            </div>
        </div>
    );
}

function CreateAssignment({ token, classId, onCreated }) {
    const [title, setTitle] = useState("Homework 1");
    const [desc, setDesc] = useState("");
    const [due, setDue] = useState(
        new Date(Date.now() + 24 * 3600e3).toISOString().slice(0, 16)
    ); // datetime-local value
    const [busy, setBusy] = useState(false);
    async function submit(e) {
        e.preventDefault();
        setBusy(true);
        try {
            const iso = new Date(due).toISOString();
            const r = await apiPost(
                `/classrooms/${classId}/assignments`,
                token,
                { title, description: desc || null, due_at: iso }
            );
            onCreated?.(r);
        } catch (e) {
            alert(e.message);
        } finally {
            setBusy(false);
        }
    }
    return (
        <Card>
            <h3 style={S.h3}>Create assignment</h3>
            <form onSubmit={submit} style={S.form}>
                <label style={S.label}>
                    Title
                    <input
                        style={S.input}
                        value={title}
                        onChange={(e) => setTitle(e.target.value)}
                        required
                    />
                </label>
                <label style={S.label}>
                    Description
                    <textarea
                        style={S.textarea}
                        value={desc}
                        onChange={(e) => setDesc(e.target.value)}
                    />
                </label>
                <label style={S.label}>
                    Due at
                    <input
                        type="datetime-local"
                        style={S.input}
                        value={due}
                        onChange={(e) => setDue(e.target.value)}
                        required
                    />
                </label>
                <button style={S.primary} disabled={busy}>
                    {busy ? "Creating…" : "Create"}
                </button>
            </form>
        </Card>
    );
}

function AssignmentDetail({ token, me, assignmentId }) {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);
    useEffect(() => {
        let gone = false;
        (async () => {
            try {
                setLoading(true);
                const r = await apiGet(`/assignments/${assignmentId}`, token);
                if (!gone) setData(r);
            } catch (e) {
                alert(e.message);
            } finally {
                if (!gone) setLoading(false);
            }
        })();
        return () => {
            gone = true;
        };
    }, [assignmentId]);

    if (loading) return <p>Loading…</p>;
    if (!data) return <p style={S.muted}>Not found</p>;

    return (
        <div style={{ display: "grid", gap: 12 }}>
            <h3 style={S.h3}>{data.title}</h3>
            {data.description && <p style={S.subtle}>{data.description}</p>}
            <Row label="Due" value={new Date(data.due_at).toLocaleString()} />

            <Card>
                <h4 style={S.h3}>Attachments</h4>
                {me.role === "teacher" && (
                    <UploadAssignmentAttachment
                        token={token}
                        assignmentId={data.id}
                        onDone={async () => {
                            const r = await apiGet(
                                `/assignments/${assignmentId}`,
                                token
                            );
                            setData(r);
                        }}
                    />
                )}
                {data.attachments?.length ? (
                    <ul style={S.list}>
                        {data.attachments.map((f) => (
                            <li key={f.id} style={S.listItem}>
                                <div>
                                    {f.filename}{" "}
                                    <span style={S.subtle}>
                                        ({f.size_bytes || "?"} bytes)
                                    </span>
                                </div>
                                <button
                                    style={S.pill}
                                    onClick={async () => {
                                        const { url } = await apiPost(
                                            `/assignments/${data.id}/attachments/${f.id}/presign-download`,
                                            token
                                        );
                                        window.open(url, "_blank");
                                    }}
                                >
                                    Download
                                </button>
                            </li>
                        ))}
                    </ul>
                ) : (
                    <p style={S.muted}>No files.</p>
                )}
            </Card>

            <Card>
                <h4 style={S.h3}>Submission</h4>
                {me.role === "teacher" ? (
                    <TeacherSubmissions token={token} assignmentId={data.id} />
                ) : (
                    <StudentSubmission token={token} assignmentId={data.id} />
                )}
            </Card>
        </div>
    );
}

function UploadAssignmentAttachment({ token, assignmentId, onDone }) {
    const [file, setFile] = useState(null);
    const [busy, setBusy] = useState(false);
    async function upload() {
        if (!file) return;
        setBusy(true);
        try {
            const contentType = file.type || "application/octet-stream";
            const pre = await apiPost(
                `/assignments/${assignmentId}/attachments/presign`,
                token,
                { filename: file.name, contentType }
            );
            await putPresigned(pre.url, file, contentType);
            await apiPost(
                `/assignments/${assignmentId}/attachments/commit`,
                token,
                { key: pre.key, filename: file.name, size: file.size }
            );
            setFile(null);
            onDone?.();
        } catch (e) {
            alert(e.message);
        } finally {
            setBusy(false);
        }
    }
    return (
        <div
            style={{
                display: "flex",
                gap: 8,
                alignItems: "center",
                marginBottom: 8,
            }}
        >
            <input
                type="file"
                onChange={(e) => setFile(e.target.files?.[0] || null)}
            />
            <button
                style={S.secondary}
                disabled={!file || busy}
                onClick={upload}
            >
                {busy ? "Uploading…" : "Upload"}
            </button>
        </div>
    );
}

function StudentSubmission({ token, assignmentId }) {
    const [mine, setMine] = useState(null);
    const [file, setFile] = useState(null);
    const [busy, setBusy] = useState(false);
    useEffect(() => {
        let gone = false;
        (async () => {
            try {
                const r = await apiGet(
                    `/assignments/${assignmentId}/submissions/me`,
                    token
                );
                if (!gone) setMine(r);
            } catch (e) {
                console.warn(e);
            }
        })();
        return () => {
            gone = true;
        };
    }, [assignmentId]);

    async function submit() {
        if (!file) return;
        setBusy(true);
        try {
            const contentType = file.type || "application/octet-stream";
            const pre = await apiPost(
                `/assignments/${assignmentId}/submissions/presign`,
                token,
                { filename: file.name, contentType }
            );
            await putPresigned(pre.url, file, contentType);
            const r = await apiPost(
                `/assignments/${assignmentId}/submissions/commit`,
                token,
                { key: pre.key, filename: file.name, size: file.size }
            );
            setMine(r);
            setFile(null);
        } catch (e) {
            alert(e.message);
        } finally {
            setBusy(false);
        }
    }

    if (mine) {
        return (
            <div>
                <p>
                    Submitted: <b>{mine.filename}</b> ({mine.size_bytes || "?"}{" "}
                    bytes) at {new Date(mine.submitted_at).toLocaleString()}
                </p>
            </div>
        );
    }
    return (
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <input
                type="file"
                onChange={(e) => setFile(e.target.files?.[0] || null)}
            />
            <button style={S.primary} disabled={!file || busy} onClick={submit}>
                {busy ? "Submitting…" : "Submit once"}
            </button>
        </div>
    );
}

function TeacherSubmissions({ token, assignmentId }) {
    const [rows, setRows] = useState([]);
    const [loading, setLoading] = useState(true);
    useEffect(() => {
        let gone = false;
        (async () => {
            try {
                setLoading(true);
                const r = await apiGet(
                    `/assignments/${assignmentId}/submissions`,
                    token
                );
                if (!gone) setRows(r);
            } catch (e) {
                alert(e.message);
            } finally {
                if (!gone) setLoading(false);
            }
        })();
        return () => {
            gone = true;
        };
    }, [assignmentId]);

    if (loading) return <p>Loading…</p>;
    return rows.length ? (
        <ul style={S.list}>
            {rows.map((s) => (
                <li key={s.id} style={S.listItem}>
                    <div>
                        <div style={S.title}>{s.name || s.email}</div>
                        <div style={S.subtle}>
                            {s.filename} • {s.size_bytes || "?"} bytes •{" "}
                            {new Date(s.submitted_at).toLocaleString()}
                        </div>
                    </div>
                    <button
                        style={S.pill}
                        onClick={async () => {
                            const { url } = await apiPost(
                                `/assignments/${assignmentId}/submissions/${s.id}/presign-download`,
                                token
                            );
                            window.open(url, "_blank");
                        }}
                    >
                        Download
                    </button>
                </li>
            ))}
        </ul>
    ) : (
        <p style={S.muted}>No submissions yet.</p>
    );
}

// ====== MATERIALS ======
function MaterialsTab({ token, me, cls }) {
    const [list, setList] = useState([]);
    const [file, setFile] = useState(null);
    const [busy, setBusy] = useState(false);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        let gone = false;
        (async () => {
            try {
                setLoading(true);
                const r = await apiGet(
                    `/classrooms/${cls.id}/materials`,
                    token
                );
                if (!gone) setList(r);
            } catch (e) {
                alert(e.message);
            } finally {
                if (!gone) setLoading(false);
            }
        })();
        return () => {
            gone = true;
        };
    }, [cls.id]);

    async function upload() {
        if (!file) return;
        setBusy(true);
        try {
            const ct = file.type || "application/octet-stream";
            const pre = await apiPost(
                `/classrooms/${cls.id}/materials/presign`,
                token,
                { filename: file.name, contentType: ct }
            );
            await putPresigned(pre.url, file, ct);
            const meta = await apiPost(
                `/classrooms/${cls.id}/materials/commit`,
                token,
                { key: pre.key, filename: file.name, size: file.size }
            );
            setList([meta, ...list]);
            setFile(null);
        } catch (e) {
            alert(e.message);
        } finally {
            setBusy(false);
        }
    }

    return (
        <div style={{ display: "grid", gap: 12 }}>
            {me.role === "teacher" && (
                <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                    <input
                        type="file"
                        onChange={(e) => setFile(e.target.files?.[0] || null)}
                    />
                    <button
                        style={S.secondary}
                        disabled={!file || busy}
                        onClick={upload}
                    >
                        {busy ? "Uploading…" : "Upload material"}
                    </button>
                </div>
            )}

            {loading ? (
                <p>Loading…</p>
            ) : list.length ? (
                <ul style={S.list}>
                    {list.map((m) => (
                        <li key={m.id} style={S.listItem}>
                            <div>
                                {m.filename}{" "}
                                <span style={S.subtle}>
                                    ({m.size_bytes || "?"} bytes) •{" "}
                                    {new Date(m.uploaded_at).toLocaleString()}
                                </span>
                            </div>
                            <button
                                style={S.pill}
                                onClick={async () => {
                                    const { url } = await apiPost(
                                        `/materials/${m.id}/presign-download`,
                                        token
                                    );
                                    window.open(url, "_blank");
                                }}
                            >
                                Download
                            </button>
                        </li>
                    ))}
                </ul>
            ) : (
                <p style={S.muted}>No materials yet.</p>
            )}
        </div>
    );
}

// ====== MEMBERS ======
function MembersTab({ token, cls }) {
    const [rows, setRows] = useState([]);
    useEffect(() => {
        let gone = false;
        (async () => {
            try {
                const r = await apiGet(`/classrooms/${cls.id}/members`, token);
                if (!gone) setRows(r);
            } catch (e) {
                alert(e.message);
            }
        })();
        return () => {
            gone = true;
        };
    }, [cls.id]);

    return rows.length ? (
        <ul style={S.list}>
            {rows.map((m) => (
                <li key={m.user_id} style={S.listItem}>
                    <div style={S.title}>{m.name || m.email}</div>
                    <div style={S.subtle}>
                        {m.role_in_class} • joined{" "}
                        {new Date(m.joined_at).toLocaleString()}
                    </div>
                </li>
            ))}
        </ul>
    ) : (
        <p style={S.muted}>No members.</p>
    );
}

// ====== STYLES ======
const S = {
    page: {
        fontFamily:
            "Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial",
        background: "linear-gradient(180deg,#0f172a 0%,#0b1226 100%)",
        minHeight: "100vh",
        color: "#e5e7eb",
    },
    header: {
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "16px 24px",
        borderBottom: "1px solid rgba(255,255,255,0.08)",
    },
    brand: { fontWeight: 800, fontSize: 22 },
    avatar: {
        width: 36,
        height: 36,
        borderRadius: 999,
        background: "#334155",
        display: "grid",
        placeItems: "center",
        fontWeight: 700,
    },
    container: {
        maxWidth: 1200,
        margin: "24px auto",
        padding: "0 16px",
        display: "grid",
        gap: 16,
    },
    layout: { display: "grid", gridTemplateColumns: "1.2fr .8fr", gap: 16 },
    h1: { fontSize: 28, margin: "0 0 8px 0" },
    h2: { fontSize: 20, margin: "0 0 8px 0" },
    h3: { fontSize: 16, margin: "0 0 8px 0" },
    muted: { opacity: 0.7 },
    subtle: { opacity: 0.8, fontSize: 13 },
    card: {
        background: "rgba(255,255,255,0.06)",
        border: "1px solid rgba(255,255,255,0.08)",
        borderRadius: 16,
        padding: 16,
        backdropFilter: "blur(8px)",
    },
    list: {
        listStyle: "none",
        padding: 0,
        margin: 0,
        display: "grid",
        gap: 12,
    },
    listItem: {
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "12px 14px",
        borderRadius: 12,
        background: "rgba(255,255,255,0.04)",
        border: "1px solid rgba(255,255,255,0.06)",
        cursor: "pointer",
    },
    title: { fontWeight: 700 },
    badge: {
        marginLeft: 8,
        fontSize: 12,
        padding: "2px 8px",
        borderRadius: 999,
        background: "rgba(59,130,246,0.2)",
        border: "1px solid rgba(59,130,246,0.4)",
    },
    form: { display: "grid", gap: 12 },
    formRow: {
        display: "grid",
        gridTemplateColumns: "1fr 1fr auto",
        gap: 8,
        marginTop: 8,
    },
    label: { display: "grid", gap: 6, fontSize: 13, opacity: 0.9 },
    input: {
        padding: "10px 12px",
        borderRadius: 10,
        border: "1px solid rgba(255,255,255,0.15)",
        background: "rgba(15,23,42,0.6)",
        color: "#e5e7eb",
        outline: "none",
    },
    textarea: {
        padding: "10px 12px",
        borderRadius: 10,
        border: "1px solid rgba(255,255,255,0.15)",
        background: "rgba(15,23,42,0.6)",
        color: "#e5e7eb",
        outline: "none",
        minHeight: 80,
    },
    primary: {
        padding: "10px 14px",
        borderRadius: 12,
        border: "1px solid rgba(59,130,246,0.5)",
        background: "rgba(59,130,246,0.15)",
        color: "#e5e7eb",
        cursor: "pointer",
        fontWeight: 600,
    },
    secondary: {
        padding: "10px 14px",
        borderRadius: 12,
        border: "1px solid rgba(34,197,94,0.5)",
        background: "rgba(34,197,94,0.15)",
        color: "#e5e7eb",
        cursor: "pointer",
        fontWeight: 600,
    },
    ghost: {
        padding: "8px 12px",
        borderRadius: 12,
        border: "1px solid rgba(255,255,255,0.15)",
        background: "transparent",
        color: "#e5e7eb",
        cursor: "pointer",
        fontWeight: 600,
    },
    pill: {
        padding: "6px 10px",
        borderRadius: 999,
        border: "1px solid rgba(255,255,255,0.18)",
        background: "rgba(255,255,255,0.06)",
        color: "#e5e7eb",
        cursor: "pointer",
        fontSize: 12,
    },
    code: {
        padding: "4px 8px",
        borderRadius: 8,
        background: "rgba(2,6,23,0.6)",
        border: "1px solid rgba(255,255,255,0.12)",
        fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
        fontSize: 12,
    },
    hr: { height: 1, background: "rgba(255,255,255,0.12)", margin: "8px 0" },
    center: {
        maxWidth: 720,
        margin: "10vh auto",
        textAlign: "center",
        padding: "0 16px",
    },
    grid2: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 },
    flexBetween: {
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
    },
    tabs: { display: "flex", gap: 8, margin: "8px 0 12px" },
    tabBtn: {
        padding: "8px 12px",
        borderRadius: 999,
        border: "1px solid rgba(255,255,255,0.15)",
        background: "rgba(255,255,255,0.04)",
        color: "#e5e7eb",
        cursor: "pointer",
    },
    tabBtnActive: {
        border: "1px solid rgba(59,130,246,0.6)",
        background: "rgba(59,130,246,0.18)",
    },
};
