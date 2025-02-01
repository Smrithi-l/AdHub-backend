const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const dotenv = require('dotenv'); 
const bcrypt = require("bcryptjs"); // Updated to bcryptjs
const jwt = require("jsonwebtoken");
const Ad = require("./models/Ad"); 
const chatRoutes = require("./routes/chatRoutes");
const userRoutes = require('./routes/userRoutes');
const adRoutes = require('./routes/adRoutes');

dotenv.config();
const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(bodyParser.json());

// Connect to MongoDB
mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log('MongoDB connected successfully!'))
  .catch((err) => console.error('Failed to connect to MongoDB:', err));

// Use routes
app.use('/api/users', userRoutes);
app.use('/api/ads', adRoutes); 
app.use("/api/chat", chatRoutes);

// Admin Schema & Model
const adminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const Admin = mongoose.model("Admin", adminSchema);

// Middleware: Verify JWT Token
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(403).json({ success: false, message: "Unauthorized" });
  }

  jwt.verify(token, process.env.JWT_SECRET || "your_jwt_secret", (err, decoded) => {
    if (err) {
      return res.status(403).json({ success: false, message: "Invalid token" });
    }
    req.userId = decoded.id;
    next();
  });
};

// Admin Login Route
app.post("/api/admin/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const admin = await Admin.findOne({ email });
    if (!admin || !bcrypt.compareSync(password, admin.password)) {
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    const token = jwt.sign({ id: admin._id }, process.env.JWT_SECRET || "your_jwt_secret", {
      expiresIn: "1h",
    });

    res.json({ success: true, token });
  } catch (error) {
    res.status(500).json({ success: false, message: "Something went wrong", error });
  }
});

// Fetch All Ads (Admin Only)
app.get("/api/admin/ads", verifyToken, async (req, res) => {
  try {
    const ads = await Ad.find();
    res.json({ success: true, ads });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to fetch ads", error });
  }
});

// Create a New Ad (Admin Only)
app.post("/api/admin/ads", verifyToken, async (req, res) => {
  const { title, description } = req.body;
  try {
    const newAd = await Ad.create({ title, description });
    res.json({ success: true, message: "Ad created successfully", ad: newAd });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to create ad", error });
  }
});

// Seed Admin (One-Time Setup)
app.post("/api/admin/seed", async (req, res) => {
  const { email, password } = req.body;
  try {
    const existingAdmin = await Admin.findOne({ email });
    if (existingAdmin) {
      return res.status(400).json({ success: false, message: "Admin already exists" });
    }

    const hashedPassword = bcrypt.hashSync(password, 10);
    await Admin.create({ email, password: hashedPassword });

    res.json({ success: true, message: "Admin created successfully" });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to create admin", error });
  }
});

// Start the Server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});