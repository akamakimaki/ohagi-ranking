const express = require("express");
const Database = require("better-sqlite3");
const cors = require("cors");
const path = require("path");

const app = express();
const PORT = 3010;

app.use(cors());
app.use(express.json());

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

const allowedGames = new Set([
    "escape",
    "drop"
]);

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

app.listen(PORT, () => {
    console.log(
        `ohagi-ranking listening on port ${PORT}`
    );
});