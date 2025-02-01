const mongoose = require('mongoose');

const adSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  title: { type: String, required: true },
  description: { type: String, required: true },
  niche: { type: String, required: true },
  image: { type: String, required: true },
  priceRange: { type: String, required: true },
  audience: { type: String, required: true },
}, { timestamps: true });

module.exports = mongoose.model('Ad', adSchema);