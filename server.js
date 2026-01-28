// include the required modules 
const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require('bcrypt');
const jwt = require("jsonwebtoken");
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

const JWT_SECRET = process.env.JWT_SECRET;

// Login endpoint (authentication)
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  // Validate input
  if (!username || !password) {
    return res.status(400).json({ error: "Username and password are required" });
  }

  try {
    let connection = await mysql.createConnection(dbConfig);
    const [user] = await connection.execute("SELECT * FROM users WHERE username = ?", [username]);

    if (user.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Compare the password with the hashed password
    const match = await bcrypt.compare(password, user[0].password_hash);
    if (!match) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Create a token with role
    const token = jwt.sign(
      { id: user[0].user_id, username: user[0].username, role: user[0].role },  // Include the role in the payload
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    await connection.end();
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error - could not log in" });
  }
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
    req.user = payload;  // Attach the user info (including role) to the request

    // Check for admin role (if you want to protect specific routes for admins only)
    if (req.user.role !== 'admin' && req.originalUrl !== '/allspaces') {
      return res.status(403).json({ error: "Admin access required" });  // Allow students to view spaces
    }

    next();
  } catch (error) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// get all spaces (students and admins can view)
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

// add a new space (only admins can do this)
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

// update a space (only admins can do this)
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

// delete a space (only admins can do this)
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

// Registration endpoint for students
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  // Validate input (ensure username and password are provided)
  if (!username || !password) {
    return res.status(400).json({ error: "Username and password are required" });
  }

  try {
    let connection = await mysql.createConnection(dbConfig);

    // Check if the student ID already exists
    const [existingUser] = await connection.execute("SELECT * FROM users WHERE username = ?", [username]);
    if (existingUser.length > 0) {
      return res.status(400).json({ error: "Student ID is already taken" });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the new student into the database (default role as 'student')
    await connection.execute(
      "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
      [username, hashedPassword, 'student']  // Role 'student' is hardcoded here
    );

    await connection.end();
    res.status(201).json({ message: "Registration successful" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error - could not register student" });
  }
});
