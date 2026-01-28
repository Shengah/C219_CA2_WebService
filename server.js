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
    // Log the token to ensure it’s being passed correctly
    console.log("Received Token:", token);

    const payload = jwt.verify(token, JWT_SECRET);  // Decodes the token
    req.user = payload;  // Set req.user with the decoded JWT payload
    
    // Log the decoded payload (to debug)
    console.log("Decoded JWT Payload:", req.user);  // Check if user_id exists here
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

app.post("/bookspace", requireAuth, async (req, res) => {
  const { space_id, start_time, end_time } = req.body;
  
  // Log req.user to see if user_id is populated correctly
  console.log("Authenticated User:", req.user);

  const { user_id } = req.user;  // This should be populated from the JWT token

  // Check if user_id is correctly extracted
  console.log("Booking details - user_id:", user_id, "space_id:", space_id, "start_time:", start_time, "end_time:", end_time);

  if (!user_id || !space_id || !start_time || !end_time) {
    return res.status(400).json({ error: "user_id, space_id, start_time, and end_time are required" });
  }

  try {
    let connection = await mysql.createConnection(dbConfig);

    // Check if the space is available for the requested time
    const [space] = await connection.execute(
      "SELECT * FROM spaces WHERE space_id = ? AND status = 'available'",
      [space_id]
    );

    if (space.length === 0) {
      return res.status(400).json({ error: "Space is not available for booking" });
    }

    // Check if the space is available during the requested time
    const [existingBooking] = await connection.execute(
      "SELECT * FROM user_bookings WHERE space_id = ? AND (start_time < ? AND end_time > ?)",
      [space_id, end_time, start_time]
    );

    if (existingBooking.length > 0) {
      return res.status(400).json({ error: "The space is already booked for the selected time." });
    }

    // Insert the booking into the user_bookings table
    await connection.execute(
      "INSERT INTO user_bookings (user_id, space_id, start_time, end_time, status) VALUES (?, ?, ?, ?, ?)",
      [user_id, space_id, start_time, end_time, 'booked']
    );

    // Update the space status to 'reserved'
    await connection.execute(
      "UPDATE spaces SET status = 'reserved' WHERE space_id = ?",
      [space_id]
    );

    await connection.end();
    res.status(201).json({ message: "Space booked successfully!" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error - could not book space", details: err.message });
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
