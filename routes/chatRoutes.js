const express = require("express");
const ChatQuery = require("../models/chatQuery");
const router = express.Router();

// Save chat query
router.post("/", async (req, res) => {
  try {
    const { name, email, question } = req.body;
    const newQuery = new ChatQuery({ name, email, question });
    await newQuery.save();
    res.status(201).json({ message: "Query saved successfully!" });
  } catch (error) {
    res.status(500).json({ message: "Error saving query", error });
  }
});

// Get all chat queries (For admin panel)
router.get("/", async (req, res) => {
  try {
    const queries = await ChatQuery.find();
    res.json({ queries });
  } catch (error) {
    res.status(500).json({ message: "Error fetching queries", error });
  }
});

module.exports = router;