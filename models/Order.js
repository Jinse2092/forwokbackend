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
        expiryDate: String,
      quantity: Number,
    }
  ],
  // Packing details: allocations of order items to specific inventory batches
  packingDetails: [
    {
      productId: String,
      allocations: [
        {
          inventoryId: String,
          expiryDate: String,
          sourceInboundDate: String,
          used: Number
        }
      ]
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
