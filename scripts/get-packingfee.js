const mongoose = require('mongoose');

const mongoURI = 'mongodb+srv://LEO:leo112944@cluster0.ye9exkm.mongodb.net/forvoqdb?retryWrites=true&w=majority&appName=Cluster0';

async function main(orderId) {
  await mongoose.connect(mongoURI);
  console.log('Connected to MongoDB');

  const packingFeeSchema = new mongoose.Schema({}, { strict: false });
  const PackingFee = mongoose.models.PackingFee || mongoose.model('PackingFee', packingFeeSchema);

  try {
    const doc = await PackingFee.findOne({ orderId: orderId }).lean();
    if (!doc) {
      console.log(`No PackingFee document found for orderId: ${orderId}`);
    } else {
      console.log('PackingFee document:');
      console.log(JSON.stringify(doc, null, 2));
    }
  } catch (err) {
    console.error('Error querying PackingFee:', err);
  } finally {
    await mongoose.disconnect();
  }
}

if (require.main === module) {
  const id = process.argv[2];
  if (!id) {
    console.error('Usage: node get-packingfee.js <orderId>');
    process.exit(1);
  }
  main(id).then(() => process.exit(0));
}
