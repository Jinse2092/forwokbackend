const mongoose = require('mongoose');

const productSchema = new mongoose.Schema({
  id: String,
  name: String,
  sku: { type: String, default: '' }, // Ensure sku is always present
  category: { type: String, default: '' }, // Ensure category is always present
  merchantId: String,
  weightKg: Number,
  lengthCm: Number,
  breadthCm: Number,
  heightCm: Number,
  // New fee fields: per-item transportation, per-item packing, and warehousing rate per kg
  transportationFee: { type: Number, default: 0 },
  itemPackingFee: { type: Number, default: 0 },
  warehousingRatePerKg: { type: Number, default: 0 },
  price: { type: Number, default: 0 }, // Ensure price is always present
  cost: { type: Number, default: 0 }   // Ensure cost is always present
});

module.exports = mongoose.model('Product', productSchema);
