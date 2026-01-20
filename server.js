const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
require('dotenv').config();
const port = 3000;

// Database Configuration
const dbConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT,
    ssl: { rejectUnauthorized: false },
    waitForConnections: true,
    connectionLimit: 100,
    queueLimit: 0,
};

const app = express();

// --- 1. CORS CONFIGURATION (The code you asked to implement) ---
const allowedOrigins = [
    "http://localhost:3000",
    // "https://YOUR-frontend.vercel.app", // add later
    // "https://YOUR-frontend.onrender.com" // add later
];

app.use(
    cors({
        origin: function (origin, callback) {
            // allow requests with no origin (Postman/server-to-server)
            if (!origin) return callback(null, true);
            if (allowedOrigins.includes(origin)) {
                return callback(null, true);
            }
            return callback(new Error("Not allowed by CORS"));
        },
        methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization"],
        credentials: false,
    })
);

app.use(express.json());

// --- 2. ROUTES ---

// GET: Fetch all cards
app.get('/allcards', async (req,res) => {
    try {
        let connection = await mysql.createConnection(dbConfig);
        const [rows] = await connection.execute('SELECT * FROM defaultdb.cards');
        await connection.end();
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({message: 'Server error for allcards'});
    }
});

// POST: Add a new card
app.post('/addcard', async (req, res) => {
    const { card_name, card_pic } = req.body;
    try {
        let connection = await mysql.createConnection(dbConfig);
        await connection.execute(
            'INSERT INTO defaultdb.cards (card_name, card_pic) VALUES (?, ?)',
            [card_name, card_pic]
        );
        await connection.end();
        res.status(201).json({ message: 'Card ' + card_name + ' added successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error - could not add card' });
    }
});

// PUT: Update an existing card
app.put('/updatecard/:id', async (req, res) => {
    const { id } = req.params;
    const { card_name, card_pic } = req.body;
    try {
        let connection = await mysql.createConnection(dbConfig);
        await connection.execute(
            'UPDATE defaultdb.cards SET card_name = ?, card_pic = ? WHERE id = ?',
            [card_name, card_pic, id]
        );
        await connection.end();
        res.json({ message: 'Card updated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error - could not update card' });
    }
});

// DELETE: Delete a card
app.delete('/deletecard/:id', async (req, res) => {
    const { id } = req.params;
    try {
        let connection = await mysql.createConnection(dbConfig);
        await connection.execute(
            'DELETE FROM defaultdb.cards WHERE id = ?',
            [id]
        );
        await connection.end();
        res.json({ message: 'Card deleted successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error - could not delete card' });
    }
});

// --- 3. START SERVER ---
app.listen(port, () => {
    console.log('Server started on port, port');
});
