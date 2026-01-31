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

// Login (authentication) (Li Sheng)
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

// Middleware to protect routes (Li Sheng)
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


// Get all spaces (Li Sheng)
app.get("/allspaces", async (req, res) => {
  try {
    const { location, status } = req.query; // Retrieve query params for location and status

    let connection = await mysql.createConnection(dbConfig);

    // Start building the SQL query
    let query = `
      SELECT spaces.*, 
             user_bookings.user_id AS bookedByUserId, 
             users.username AS bookedByUserName
        FROM spaces
        LEFT JOIN user_bookings 
          ON spaces.space_id = user_bookings.space_id 
          AND user_bookings.status = 'booked'
        LEFT JOIN users 
          ON user_bookings.user_id = users.user_id
        WHERE 1=1`; // Always true condition for dynamic filtering

    // Add filters based on query parameters
    if (location) {
      query += ` AND spaces.location LIKE '%${location}%'`;  // Filter by location if provided
    }

    if (status) {
      query += ` AND spaces.status = '${status}'`;  // Filter by status if provided
    }

    // Execute the query
    const [spaces] = await connection.execute(query);

    await connection.end();

    // Respond with filtered spaces
    res.json(spaces);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error for allspaces" });
  }
});


// Add a new space (Xing Herng)
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

// Update a space (Li Sheng)
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


// Admin can delete a space (Xing Herng)
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


// Registration endpoint for students (Li Sheng)
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


// Book Spaces (Xing Herng)
app.post("/bookspace", requireAuth, async (req, res) => { 
  const { space_id, start_time, end_time } = req.body;

  // Log the req.user object to check if user_id is defined
  console.log("Authenticated User:", req.user); // Check if req.user contains user_id

  const user_id = req.user.id;  // Correctly access the `id` property from the payload

  // Log the booking details for debugging
  console.log("Booking details - user_id:", user_id, "space_id:", space_id, "start_time:", start_time, "end_time:", end_time);

  if (!user_id || !space_id || !start_time || !end_time) {
    return res.status(400).json({ error: "user_id, space_id, start_time, and end_time are required" });
  }

  try {
    // Convert ISO 8601 datetime format to MySQL-compatible format (YYYY-MM-DD HH:MM:SS)
    const formatMySQLDatetime = (isoDate) => {
      return isoDate.replace("T", " ").replace("Z", "");  // Remove 'T' and 'Z'
    };

    const formattedStartTime = formatMySQLDatetime(start_time);
    const formattedEndTime = formatMySQLDatetime(end_time);

    console.log("Formatted Start Time:", formattedStartTime);
    console.log("Formatted End Time:", formattedEndTime);

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
      [space_id, formattedEndTime, formattedStartTime]
    );

    if (existingBooking.length > 0) {
      return res.status(400).json({ error: "The space is already booked for the selected time." });
    }

    // Insert the booking into the user_bookings table
    await connection.execute(
      "INSERT INTO user_bookings (user_id, space_id, start_time, end_time, status) VALUES (?, ?, ?, ?, ?)",
      [user_id, space_id, formattedStartTime, formattedEndTime, 'booked']
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

// Cancel Booking endpoint for students (Li Sheng)
app.post("/cancelbooking", requireAuth, async (req, res) => {
  const { space_id } = req.body;
  const { id } = req.user; // The authenticated user's ID (accessing 'id' directly from req.user)

  // Log to ensure 'id' is correctly populated
  console.log("Received cancel booking request - user_id:", id, "space_id:", space_id);

  // Ensure id and space_id are not undefined before proceeding
  if (!id || !space_id) {
    return res.status(400).json({ error: "user_id and space_id are required" });
  }

  try {
    let connection = await mysql.createConnection(dbConfig);

    // Step 1: Find the booking for the student (make sure it exists and belongs to the student)
    const [booking] = await connection.execute(
      "SELECT * FROM user_bookings WHERE user_id = ? AND space_id = ? AND status = 'booked'",
      [id, space_id]
    );

    if (booking.length === 0) {
      return res.status(404).json({ error: "Booking not found or already cancelled" });
    }

    // Step 2: Delete the booking from the user_bookings table
    await connection.execute(
      "DELETE FROM user_bookings WHERE user_id = ? AND space_id = ?",
      [id, space_id]
    );

    // Step 3: Update the space status to 'available'
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

// View user bookings (Xing Herng)
app.get("/viewbooking", requireAuth, async (req, res) => {
  const { id } = req.user;

  try {
    let connection = await mysql.createConnection(dbConfig);

    const [rows] = await connection.execute(
      `
      SELECT 
        ub.booking_id,
        ub.space_id,
        ub.start_time,
        ub.end_time,
        ub.status,
        s.name AS space_name,
        s.location,
        s.image_url
      FROM user_bookings ub
      JOIN spaces s ON ub.space_id = s.space_id
      WHERE ub.user_id = ?
      `,
      [id]
    );

    await connection.end();
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error - could not fetch bookings" });
  }
});


// Scheduled task to delete expired spaces every hour
cron.schedule('* * * * *', async () => {  // Runs every minute for testing
  try {
    let connection = await mysql.createConnection(dbConfig);

    // Step 1: Delete the related user bookings
    await connection.execute(
      "DELETE FROM user_bookings WHERE space_id IN (SELECT space_id FROM spaces WHERE end_time < CONVERT_TZ(NOW(), 'UTC', 'Asia/Singapore') AND status = 'booked')"
    );

    // Step 2: Now delete the expired spaces
    await connection.execute(
      "DELETE FROM spaces WHERE end_time < CONVERT_TZ(NOW(), 'UTC', 'Asia/Singapore') AND status = 'reserved'"
    );

    await connection.end();
    console.log("Expired spaces and related bookings deleted successfully.");
  } catch (err) {
    console.error("Error deleting expired spaces: ", err);
  }
});





module.exports = app;
