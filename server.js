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
//   "https://card-app-smoky.vercel.app",
  "https://card-app-starter-team2-0uw1.onrender.com/"
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

// get all cards
app.get("/allcards", async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT * FROM cards");
    res.json(rows);
  } catch (error) {
    console.error("Error fetching cards:", error);
    res
      .status(500)
      .json({ error: "Internal Server Error for getting all cards" });
  }
});

// add a new card
app.post("/addcard", async (req, res) => {
  const { card_name, card_pic } = req.body;

  if (!card_name || !card_pic) {
    return res
      .status(400)
      .json({ error: "card_name and card_pic are required" });
  }

  try {
    const [result] = await pool.query(
      "INSERT INTO cards (card_name, card_pic) VALUES (?, ?)",
      [card_name, card_pic]
    );
    res.status(201).json(result);
  } catch (error) {
    console.error("Error adding card:", error);
    res.status(500).json({ error: "Internal Server Error for adding a card" });
  }
});

// update a card, week 10
app.put("/updatecard/:id", async (req, res) => {
  const { id } = req.params;
  const { card_name, card_pic } = req.body;

  if (!card_name || !card_pic) {
    return res
      .status(400)
      .json({ error: "card_name and card_pic are required" });
  }

  try {
    const [result] = await pool.query(
      "UPDATE cards SET card_name = ?, card_pic = ? WHERE id = ?",
      [card_name, card_pic, id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Card not found" });
    }

    res
      .status(200)
      .json({ message: "Card updated", affectedRows: result.affectedRows });
  } catch (error) {
    console.error("Error updating card:", error);
    res
      .status(500)
      .json({ error: "Internal Server Error for updating a card" });
  }
});

// delete a card, week 10
app.delete("/deletecard/:id", async (req, res) => {
  const { id } = req.params;

  try {
    const [result] = await pool.query("DELETE FROM cards WHERE id = ?", [id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Card not found" });
    }

    res
      .status(200)
      .json({ message: "Card deleted", affectedRows: result.affectedRows });
  } catch (error) {
    console.error("Error deleting card:", error);
    res
      .status(500)
      .json({ error: "Internal Server Error for deleting a card" });
  }
});
