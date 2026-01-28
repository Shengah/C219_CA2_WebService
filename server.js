// include the required modules 
const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require('bcrypt');
const jwt = require("jsonwebtoken");
require("dotenv").config();
const cron = require('node-cron'); // Import node-cron for scheduling tasks

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
      { id: user[0].user_id, username: user[0].username, role: user[0].role },
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
    req.user = payload;

    // Check for admin role (if you want to protect specific routes for admins only)
    if (req.user.role !== 'admin' && req.originalUrl !== '/allspaces') {
      return res.status(403).json({ error: "Admin access required" });  // Allow students to view spaces
    }

    next();
  } catch (error) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// Get all spaces (students and admins can view)
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

// Add a new space (only admins can do this)
app.post("/addspace", requireAuth, async (req, res) => {
  const { name, location, status, start_time, end_time, usage_notes, image_url } = req.body;
  try {
    let connection = await mysql.createConnection(dbConfig);
    await connection.execute(
      "INSERT INTO spaces (name, location, status, start_time, end_time, usage_notes, image_url) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [name, location, status, start_time, end_time, usage_notes, image_url]
    );
    await connection.end();
    res.status(201).json({ message: `Space ${name} added successfully` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error - could not add space" });
  }
});

// Update a space (only admins can do this)
app.put("/updatespace/:id", requireAuth, async (req, res) => {
  const { id } = req.params;
  const { name, location, status, start_time, end_time, usage_notes, image_url } = req.body;
  try {
    let connection = await mysql.createConnection(dbConfig);
    await connection.execute(
      "UPDATE spaces SET name=?, location=?, status=?, start_time=?, end_time=?, usage_notes=?, image_url=? WHERE space_id=?",
      [name, location, status, start_time, end_time, usage_notes, image_url, id]
    );
    res.status(201).json({ message: `Space ${id} updated successfully!` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: `Server error - could not update space ${id}` });
  }
});

// Admin can delete a space completely (delete space and all bookings related to it)
app.delete("/deletespace/:id", requireAuth, async (req, res) => {
  const { id } = req.params;

  // Only admin can delete a space
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: "Unauthorized - Admin only action" });
  }

  try {
    let connection = await mysql.createConnection(dbConfig);

    // Step 1: Delete the space (admin deletes the space)
    const [result] = await connection.execute("DELETE FROM spaces WHERE space_id=?", [id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Space not found" });
    }

    // Step 2: Optionally, remove associated bookings if necessary
    await connection.execute("DELETE FROM user_bookings WHERE space_id=?", [id]);

    await connection.end();
    res.status(200).json({ message: "Space and its bookings deleted successfully!" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error - could not delete space" });
  }
});


// Admin can delete a space completely (delete space and all bookings related to it)
app.delete("/deletespace/:id", requireAuth, async (req, res) => {
  const { id } = req.params;

  // Only admin can delete a space
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: "Unauthorized - Admin only action" });
  }

  try {
    let connection = await mysql.createConnection(dbConfig);

    // Step 1: Delete the space (admin deletes the space)
    const [result] = await connection.execute("DELETE FROM spaces WHERE space_id=?", [id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Space not found" });
    }

    // Step 2: Optionally, remove associated bookings if necessary
    await connection.execute("DELETE FROM user_bookings WHERE space_id=?", [id]);

    await connection.end();
    res.status(200).json({ message: "Space and its bookings deleted successfully!" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error - could not delete space" });
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

// Book a space (student booking the space and update space status to reserved)
app.post("/bookspace", requireAuth, async (req, res) => {
  const { space_id, start_time, end_time } = req.body;
  const { user_id } = req.user;

  try {
    let connection = await mysql.createConnection(dbConfig);

    // Step 1: Check if the space is available for booking
    const [space] = await connection.execute(
      "SELECT * FROM spaces WHERE space_id = ? AND status = 'available'",
      [space_id]
    );

    if (space.length === 0) {
      return res.status(400).json({ error: "Space is not available for booking" });
    }

    // Step 2: Insert the booking details into the user_bookings table
    await connection.execute(
      "INSERT INTO user_bookings (user_id, space_id, start_time, end_time, status) VALUES (?, ?, ?, ?, ?)",
      [user_id, space_id, start_time, end_time, 'booked']
    );

    // Step 3: Update the space status to 'reserved'
    await connection.execute(
      "UPDATE spaces SET status = 'reserved' WHERE space_id = ?",
      [space_id]
    );

    await connection.end();
    res.status(201).json({ message: "Space booked successfully!" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error - could not book space" });
  }
});



// Cancel Booking endpoint for students
app.post("/cancelbooking", requireAuth, async (req, res) => {
  const { space_id } = req.body;
  const { user_id } = req.user; // The authenticated user's ID

  try {
    let connection = await mysql.createConnection(dbConfig);

    // Step 1: Find the booking for the student (make sure it exists and belongs to the student)
    const [booking] = await connection.execute(
      "SELECT * FROM user_bookings WHERE user_id = ? AND space_id = ? AND status = 'booked'",
      [user_id, space_id]
    );

    if (booking.length === 0) {
      return res.status(404).json({ error: "Booking not found or already cancelled" });
    }

    // Step 2: Update the booking status to 'cancelled' and set the space status to 'available'
    await connection.execute(
      "UPDATE user_bookings SET status = 'cancelled' WHERE user_id = ? AND space_id = ?",
      [user_id, space_id]
    );

    // Update the space status to 'available'
    await connection.execute(
      "UPDATE spaces SET status = 'available' WHERE space_id = ?",
      [space_id]
    );

    await connection.end();
    res.status(200).json({ message: "Booking cancelled successfully, space is now available" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error - could not cancel booking" });
  }
});

// Scheduled task to delete expired spaces every hour
cron.schedule('0 * * * *', async () => {  // Runs every hour
  try {
    let connection = await mysql.createConnection(dbConfig);

    // Delete spaces that have passed their end_time and are reserved
    await connection.execute(
      "DELETE FROM spaces WHERE end_time < NOW() AND status = 'reserved'"
    );

    await connection.end();
    console.log("Expired spaces deleted successfully.");
  } catch (err) {
    console.error("Error deleting expired spaces: ", err);
  }
});

module.exports = app;
