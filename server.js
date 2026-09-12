const express = require("express");
const Database = require("better-sqlite3");
const cors = require("cors");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = 3010;

app.use(cors({
    origin: [
        "https://akamakimaki.github.io",
        "http://localhost:5500",
        "http://127.0.0.1:5500"
    ],
    credentials: true
}));

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const db = new Database(
    path.join(__dirname, "ranking.db")
);

db.exec(`
    CREATE TABLE IF NOT EXISTS scores (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        game TEXT NOT NULL,
        name TEXT NOT NULL,
        score INTEGER NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
`);


db.exec(`
    CREATE TABLE IF NOT EXISTS private_scores (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        did TEXT NOT NULL,
        game TEXT NOT NULL,
        score INTEGER NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
`);

db.exec(`
    CREATE TABLE IF NOT EXISTS login_sessions (
        token_hash TEXT PRIMARY KEY,
        did TEXT NOT NULL,
        expires_at INTEGER NOT NULL
    )
`);

const allowedGames = new Set([
    "escape",
    "drop"
]);

const pendingScoreLogins =
    new Map();

function normalizeName(value) {
    const name =
        String(value || "")
            .trim()
            .slice(0, 20);

    return name || "名無し";
}

function normalizeScore(value) {
    const score =
        Number.parseInt(value, 10);

    if (!Number.isFinite(score)) {
        return null;
    }

    if (score < 0) {
        return null;
    }

    return score;
}

function hashSessionToken(token) {
    return crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");
}

function parseCookies(req) {
    const cookies = {};

    const header =
        String(req.headers.cookie || "");

    for (const part of header.split(";")) {
        const index = part.indexOf("=");

        if (index === -1) {
            continue;
        }

        const key =
            part.slice(0, index).trim();

        const value =
            part.slice(index + 1).trim();

        if (key) {
            cookies[key] =
                decodeURIComponent(value);
        }
    }

    return cookies;
}

function getLoggedInDid(req) {
    const cookies =
        parseCookies(req);

    const token =
        cookies.ohagi_session;

    if (!token) {
        return null;
    }

    const tokenHash =
        hashSessionToken(token);

    const row =
        db.prepare(`
            SELECT did
            FROM login_sessions
            WHERE token_hash = ?
              AND expires_at > ?
        `).get(
            tokenHash,
            Date.now()
        );

    return row?.did || null;
}

function requireLogin(req, res, next) {
    const did =
        getLoggedInDid(req);

    if (!did) {
        return res.status(401).json({
            error: "login_required"
        });
    }

    req.loginDid = did;

    next();
}


app.get("/health", (req, res) => {
    res.json({
        ok: true
    });
});

app.post("/api/scores", (req, res) => {
    const game = req.body.game;
    const name =
        normalizeName(req.body.name);

    const score =
        normalizeScore(req.body.score);

    if (!allowedGames.has(game)) {
        return res.status(400).json({
            error: "invalid_game"
        });
    }

    if (score === null) {
        return res.status(400).json({
            error: "invalid_score"
        });
    }

    const statement =
        db.prepare(`
            INSERT INTO scores (
                game,
                name,
                score
            )
            VALUES (?, ?, ?)
        `);

    const result =
        statement.run(
            game,
            name,
            score
        );

    res.status(201).json({
        ok: true,
        id: result.lastInsertRowid
    });
});

app.get("/api/ranking", (req, res) => {
    const game = req.query.game;

    if (!allowedGames.has(game)) {
        return res.status(400).json({
            error: "invalid_game"
        });
    }

    const rows =
        db.prepare(`
            SELECT
                id,
                game,
                name,
                score,
                created_at
            FROM scores
            WHERE game = ?
            ORDER BY
                score DESC,
                created_at ASC
            LIMIT 20
        `).all(game);

    res.json({
        game,
        ranking: rows
    });
});


app.get(
    "/api/me",
    requireLogin,
    (req, res) => {

        res.json({
            ok: true,
            did: req.loginDid
        });
    }
);

app.post(
    "/api/my-scores",
    requireLogin,
    (req, res) => {

        const game =
            req.body.game;

        const score =
            normalizeScore(
                req.body.score
            );

        if (!allowedGames.has(game)) {
            return res.status(400).json({
                error: "invalid_game"
            });
        }

        if (score === null) {
            return res.status(400).json({
                error: "invalid_score"
            });
        }

        const result =
            db.prepare(`
                INSERT INTO private_scores (
                    did,
                    game,
                    score
                )
                VALUES (?, ?, ?)
            `).run(
                req.loginDid,
                game,
                score
            );

        res.status(201).json({
            ok: true,
            id: result.lastInsertRowid
        });
    }
);

app.get(
    "/api/my-scores",
    requireLogin,
    (req, res) => {

        const game =
            req.query.game;

        if (!allowedGames.has(game)) {
            return res.status(400).json({
                error: "invalid_game"
            });
        }

        const rows =
            db.prepare(`
                SELECT
                    id,
                    game,
                    score,
                    created_at
                FROM private_scores
                WHERE did = ?
                  AND game = ?
                ORDER BY
                    created_at DESC
                LIMIT 100
            `).all(
                req.loginDid,
                game
            );

        res.json({
            game,
            scores: rows
        });
    }
);


import("./oauth.mjs")
    .then(({ oauthClient }) => {

        app.get(
            "/client-metadata.json",
            (req, res) => {

                res.json(
                    oauthClient.clientMetadata
                );
            }
        );

        app.get(
            "/jwks.json",
            (req, res) => {

                res.json(
                    oauthClient.jwks
                );
            }
        );

        app.get(
            "/login",
            async (req, res, next) => {

                try {

                    const handle =
                        String(
                            req.query.handle || ""
                        ).trim();

                    if (!handle) {

                        return res.status(400).json({
                            error: "handle_required"
                        });
                    }

                    const state =
                        crypto.randomUUID();

                    const game =
                        String(
                            req.query.game || ""
                        );

                    const score =
                        normalizeScore(
                            req.query.score
                        );

                    if (
                        allowedGames.has(game) &&
                        score !== null
                    ) {

                        pendingScoreLogins.set(
                            state,
                            {
                                game,
                                score
                            }
                        );
                    }

                    const url =
                        await oauthClient.authorize(
                            handle,
                            {
                                state
                            }
                        );

                    res.redirect(url);

                } catch (error) {

                    next(error);
                }
            }
        );

        app.get(
            "/atproto-oauth-callback",
            async (req, res, next) => {

                try {

                    const params =
                        new URLSearchParams(
                            req.url.split("?")[1] || ""
                        );

                    const oauthState =
                        params.get("state");

                    const pendingScore =
                        oauthState
                            ? pendingScoreLogins.get(
                                oauthState
                            )
                            : null;

                    const {
                        session
                    } =
                        await oauthClient.callback(
                            params
                        );

                    const sessionToken =
                        crypto
                            .randomBytes(32)
                            .toString("base64url");

                    const tokenHash =
                        hashSessionToken(
                            sessionToken
                        );

                    const expiresAt =
                        Date.now() +
                        30 * 24 * 60 * 60 * 1000;

                    db.prepare(`
    INSERT INTO login_sessions (
        token_hash,
        did,
        expires_at
    )
    VALUES (?, ?, ?)
`).run(
                        tokenHash,
                        session.did,
                        expiresAt
                    );

                    res.cookie(
                        "ohagi_session",
                        sessionToken,
                        {
                            httpOnly: true,
                            secure: true,
                            sameSite: "none",
                            maxAge:
                                30 * 24 * 60 * 60 * 1000,
                            path: "/"
                        }
                    );

                    if (pendingScore) {

                        db.prepare(`
        INSERT INTO private_scores (
            did,
            game,
            score
        )
        VALUES (?, ?, ?)
    `).run(
                            session.did,
                            pendingScore.game,
                            pendingScore.score
                        );

                        pendingScoreLogins.delete(
                            oauthState
                        );

                        return res.redirect(
                            `/?game=${encodeURIComponent(
                                pendingScore.game
                            )}&view=mine`
                        );
                    }

                    res.redirect(
                        "/?game=drop&view=mine"
                    );

                } catch (error) {

                    next(error);
                }
            }
        );

        app.listen(PORT, () => {

            console.log(
                `ohagi-ranking listening on port ${PORT}`
            );
        });
    })
    .catch(error => {

        console.error(
            "OAuth initialization failed",
            error
        );

        process.exit(1);
    });
