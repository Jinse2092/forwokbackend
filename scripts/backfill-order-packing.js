const mongoose = require('mongoose');
const path = require('path');

// Connect to same MongoDB used by server.cjs
const mongoURI = 'mongodb+srv://LEO:leo112944@cluster0.ye9exkm.mongodb.net/forvoqdb?retryWrites=true&w=majority&appName=Cluster0';

async function main(orderIdOrInternalId) {
  await mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true });
  console.log('Connected to MongoDB');

  // Define minimal Product model (reuse existing if present)
  const productSchema = new mongoose.Schema({}, { strict: false });
  const Product = mongoose.models.Product || mongoose.model('Product', productSchema);

  // Define minimal Order model
  const orderSchema = new mongoose.Schema({}, { strict: false });
  const Order = mongoose.models.Order || mongoose.model('Order', orderSchema);

  // Utility functions copied from frontend utils
  const calculateVolumetricWeight = (length, width, height) => {
    if (!length || !width || !height) return 0;
    return (length * width * height) / 5000;
  };

  const calculateDispatchFee = (actualWeight, volumetricWeight, packingType) => {
    const weight = Math.max(actualWeight || 0, volumetricWeight || 0);
    let baseFee = 7;
    let additionalFeePerHalfKg = 2;

    switch ((packingType || '').toLowerCase()) {
      case 'fragile packing':
        baseFee = 11; additionalFeePerHalfKg = 4; break;
      case 'eco friendly fragile packing':
        baseFee = 12; additionalFeePerHalfKg = 5; break;
      case 'normal packing':
      default:
        baseFee = 7; additionalFeePerHalfKg = 2; break;
    }
    if (weight <= 0.5) return baseFee;
    const additionalUnits = Math.ceil((weight - 0.5) / 0.5);
    return baseFee + additionalUnits * additionalFeePerHalfKg;
  };

  try {
    // Try find by public id first, then by _id
    let order = await Order.findOne({ id: orderIdOrInternalId });
    if (!order) {
      try {
        order = await Order.findById(orderIdOrInternalId);
      } catch (e) {
        // ignore
      }
    }
    if (!order) {
      console.error('Order not found with id or _id:', orderIdOrInternalId);
      process.exit(1);
    }

    console.log('Found order:', order.id || order._id);
    const inputIdentifier = orderIdOrInternalId;

    // Compute item-wise components
    let itemsPackingTotal = 0;
    const updatedItems = [];
    for (const it of (order.items || [])) {
      const prod = await Product.findOne({ id: it.productId }) || await Product.findById(it.productId) || {};
      const actual = Number(prod.weightKg || it.weightPerItemKg || 0);
      const vol = calculateVolumetricWeight(Number(prod.lengthCm || 0), Number(prod.breadthCm || 0), Number(prod.heightCm || 0));

      const packing = (prod.itemPackingFee !== undefined && prod.itemPackingFee !== null && prod.itemPackingFee !== '')
        ? Number(prod.itemPackingFee) || 0
        : calculateDispatchFee(actual, vol, prod.packingType || 'normal packing');
      const transportation = Number(prod.transportationFee || 0);
      const warehousing = (Number(prod.warehousingRatePerKg || 0)) * (Number(prod.weightKg || actual || 0));

      const perItemTotal = packing + transportation + warehousing;
      const qty = Number(it.quantity || 0);
      itemsPackingTotal += perItemTotal * qty;

      updatedItems.push({
        ...it,
        packingComponents: {
          packing: Number(packing.toFixed(2)),
          transportation: Number(transportation.toFixed(2)),
          warehousing: Number(warehousing.toFixed(2)),
          perItemTotal: Number(perItemTotal.toFixed(2)),
          lineTotal: Number((perItemTotal * qty).toFixed(2))
        }
      });
    }

    const existingBoxFee = (order.boxFee !== undefined && order.boxFee !== null) ? Number(order.boxFee) : 0;
    const existingBoxCutting = !!order.boxCutting;
    const trackingFee = (order.trackingFee !== undefined && order.trackingFee !== null) ? Number(order.trackingFee) : 3;
    const boxCuttingCharge = existingBoxCutting ? 2 : 0;

    const totalPackingFee = Number((itemsPackingTotal + existingBoxFee + boxCuttingCharge + trackingFee).toFixed(2));

    // Update order fields
    order.boxFee = existingBoxFee;
    order.boxCutting = existingBoxCutting;
    order.trackingFee = trackingFee;
    order.packingFee = totalPackingFee;
    order.items = updatedItems;

    const saved = await order.save();
    console.log('Order updated and saved. packingFee =', saved.packingFee);
    console.log('Saved order id:', saved.id || saved._id);

    // Also upsert a PackingFee document for this order for convenience
    try {
      const packingFeeSchema = new mongoose.Schema({}, { strict: false });
      const PackingFee = mongoose.models.PackingFee || mongoose.model('PackingFee', packingFeeSchema);
      const pfDoc = {
        // Prefer the identifier the caller provided (public id like ord-...), otherwise store the DB _id
        orderId: (typeof inputIdentifier === 'string' && inputIdentifier.startsWith('ord-')) ? inputIdentifier : (saved.id || saved._id),
        merchantId: saved.merchantId,
        items: (saved.items || []).map(it => ({
          productId: it.productId,
          name: it.name,
          quantity: it.quantity,
          warehousingPerItem: it.packingComponents ? it.packingComponents.warehousing : 0,
          transportationPerItem: it.packingComponents ? it.packingComponents.transportation : 0,
          itemPackingPerItem: it.packingComponents ? it.packingComponents.packing : 0,
          estimatedTotalPerItem: it.packingComponents ? it.packingComponents.perItemTotal : 0,
          lineTotal: it.packingComponents ? it.packingComponents.lineTotal : 0
        })),
        trackingFee: Number(saved.trackingFee || 3),
        boxFee: Number(saved.boxFee || 0),
        boxCutting: Boolean(saved.boxCutting || false),
        totalPackingFee: Number(saved.packingFee || 0),
        totalWeightKg: Number(saved.totalWeightKg || saved.packedweight || 0),
        updatedAt: new Date().toISOString()
      };
      await PackingFee.findOneAndUpdate({ orderId: pfDoc.orderId }, pfDoc, { upsert: true, new: true });
      console.log('PackingFee document upserted for order', pfDoc.orderId);
    } catch (pfErr) {
      console.error('Error upserting PackingFee in backfill:', pfErr);
    }

    await mongoose.disconnect();
    process.exit(0);
  } catch (err) {
    console.error('Error during backfill:', err);
    await mongoose.disconnect();
    process.exit(2);
  }
}

if (require.main === module) {
  const arg = process.argv[2];
  if (!arg) {
    console.error('Usage: node backfill-order-packing.js <orderId_or__id>');
    process.exit(1);
  }
  main(arg);
}
