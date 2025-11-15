const mongoose = require('mongoose');

const orderSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  merchantId: String,
  customerName: String,
  address: String,
  city: String,
  state: String,
  pincode: String,
  phone: String,
  items: [
    {
      productId: String,
      name: String,
      quantity: Number,
    }
  ],
  status: String,
  date: String,
  time: String,
  // Lifecycle timestamps
  packedAt: String,
  dispatchedAt: String,
  deliveredAt: String,
  // Courier/delivery partner
  deliveryPartner: String,
  shippingLabelBase64: String,
});

module.exports = mongoose.model('Order', orderSchema);
