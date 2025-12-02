const mongoose = require('mongoose');

const inventorySchema = new mongoose.Schema({
  id: String,
  productId: String,
  merchantId: String,
  quantity: Number,
  packedQuantity: { type: Number, default: 0 },
  location: String,
  minStockLevel: Number,
  maxStockLevel: Number,
});

module.exports = mongoose.model('Inventory', inventorySchema);
