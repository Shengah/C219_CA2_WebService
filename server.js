// include the required modules 
const express = require("express");
const mysql = require("mysql2/promise");
require("dotenv").config();

// initialize express app
const app = express();
app.use(express.json());

const port = process.env.PORT || 3000;

// database connection configuration
const dbConfig = {
  host: (process.env.DB_HOST || "").trim(),
  user: (process.env.DB_USER || "").trim(),
  password: process.env.DB_PASSWORD,
  database: (process.env.DB_NAME || "").trim(),
  port: Number(process.env.DB_PORT) || 3306,

  // pool options (these only apply when using createPool)
  waitForConnections: true,
  connectionLimit: 100,
  queueLimit: 0,
};

// create ONE pool for the whole app (do this once)
const pool = mysql.createPool(dbConfig);

// start the server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

const cors = require("cors");

const allowedOrigins = [
  "http://localhost:3000",
  "https://c219-ca-2-duqz.vercel.app"
];

app.use(
  cors({
    origin: function (origin, callback) {
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

const DEMO_USER = { id: 1, username: "admin", password: "admin123" };

const jwt = require("jsonwebtoken");
const JWT_SECRET = process.env.JWT_SECRET;

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (username !== DEMO_USER.username || password !== DEMO_USER.password) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const token = jwt.sign(
    { id: DEMO_USER.id, username: DEMO_USER.username },
    JWT_SECRET,
    { expiresIn: "1h" }
  );

  res.json({ token });
});

// Middleware to protect routes
function requireAuth(req, res, next) {
  const header = req.headers.authorization;

  if (!header) {
    return res.status(401).json({ error: "Authorization header required" });
  }

  const [type, token] = header.split(" ");
  if (type !== "Bearer" || !token) {
    return res.status(401).json({ error: "Invalid authorization format" });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (error) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// get all spaces
app.get("/allspaces", async (req, res) => {
  try {
    let connection = await mysql.createConnection(dbConfig);
    const [rows] = await connection.execute("SELECT * FROM spaces");
    await connection.end();
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error for allspaces" });
  }
});

// add a new space
app.post("/addspace", requireAuth, async (req, res) => {
  const { name, description, location, status, usage_notes } = req.body;
  try {
    let connection = await mysql.createConnection(dbConfig);
    await connection.execute(
      "INSERT INTO spaces (name, description, location, status, usage_notes) VALUES (?, ?, ?, ?, ?)",
      [name, description, location, status, usage_notes]
    );
    await connection.end();
    res.status(201).json({ message: `Space ${name} added successfully` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error - could not add space" });
  }
});

// update a space
app.put("/updatespace/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  const { name, description, location, status, usage_notes } = req.body;
  try {
    let connection = await mysql.createConnection(dbConfig);
    await connection.execute(
      "UPDATE spaces SET name=?, description=?, location=?, status=?, usage_notes=? WHERE space_id=?",
      [name, description, location, status, usage_notes, id]
    );
    res.status(201).json({ message: `Space ${id} updated successfully!` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: `Server error - could not update space ${id}` });
  }
});

// delete a space
app.delete("/deletespace/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  try {
    let connection = await mysql.createConnection(dbConfig);
    await connection.execute("DELETE FROM spaces WHERE space_id=?", [id]);
    res.status(201).json({ message: `Space ${id} deleted successfully!` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: `Server error - could not delete space ${id}` });
  }
});
