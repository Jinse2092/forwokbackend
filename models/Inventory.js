const mongoose = require('mongoose');

const inventorySchema = new mongoose.Schema({
  id: String,
  productId: String,
  merchantId: String,
  expiryDate: String,
  // The date the stock was received / associated inbound (ISO string)
  sourceInboundDate: String,
  // When this inventory record was created (ISO string)
  createdAt: String,
  quantity: Number,
  packedQuantity: { type: Number, default: 0 },
  location: String,
  minStockLevel: Number,
  maxStockLevel: Number,
});

module.exports = mongoose.model('Inventory', inventorySchema);
