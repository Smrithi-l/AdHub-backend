const express = require("express");
const { verifyToken } = require("../middleware/authMiddleware");
const Ad = require("../models/Ad");
const User = require("../models/User"); 
const router = express.Router();

router.post("/save", verifyToken, async (req, res) => {
  try {
    const { title, description, niche, image, priceRange, audience } = req.body;

    const newAd = new Ad({
      userId: req.userId, // Add user ID from token
      title,
      description,
      niche,
      image,
      priceRange,
      audience,
    });

    const savedAd = await newAd.save();
    res.status(201).json({ message: "Ad created successfully!", ad: savedAd });
  } catch (err) {
    console.error("Error creating ad:", err);
    res.status(500).json({ message: "Server error. Please try again." });
  }
});
router.get("/admin/ads", verifyToken, async (req, res) => {
  try {
    const ads = await Ad.find();
    res.status(200).json({ ads });
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch ads." });
  }
});

// Update ad status (Approve/Reject)
router.put("/admin/ad/:id", verifyToken, async (req, res) => {
  try {
    const { status } = req.body;
    const ad = await Ad.findByIdAndUpdate(req.params.id, { status }, { new: true });
    if (!ad) return res.status(404).json({ message: "Ad not found" });
    res.status(200).json({ message: "Ad status updated", ad });
  } catch (err) {
    res.status(500).json({ message: "Failed to update ad." });
  }
});
// Fetch ads for a specific user
router.get("/ads", async (req, res) => {
  const { userId } = req.query;

  if (!userId) {
    return res.status(400).json({ message: "User ID is required" });
  }

  try {
    const ads = await Ad.find({ userId }); // Ensure this matches the schema
    res.json({ ads });
  } catch (err) {
    console.error("Error fetching ads:", err);
    res.status(500).json({ message: "Server error" });
  }
});
// Fetch all clients (assuming clients are users with ads)
router.get("/admin/clients", verifyToken, async (req, res) => {
  try {
    const clients = await User.aggregate([
      { $lookup: { from: "ads", localField: "_id", foreignField: "userId", as: "ads" } },
      { $project: { name: 1, adCount: { $size: "$ads" } } }
    ]);
    res.status(200).json({ clients });
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch clients." });
  }
});


module.exports = router;