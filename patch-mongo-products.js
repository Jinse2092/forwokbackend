// patch-mongo-products.js
const mongoose = require('mongoose');
const Product = require('./models/Product');

const mongoURI = 'mongodb+srv://LEO:leo112944@cluster0.ye9exkm.mongodb.net/forvoqdb?retryWrites=true&w=majority&appName=Cluster0';

const requiredFields = {
  sku: '',
  category: '',
  price: 0,
  cost: 0,
  weightKg: 0,
  packingType: 'normal packing',
  packingPrice: 0,
  inboundPrice: 0,
  outboundPrice: 0,
  name: '',
  description: '',
  imageUrl: '',
  lengthCm: 0,
  breadthCm: 0,
  heightCm: 0
};

async function patchProducts() {
  await mongoose.connect(mongoURI);
  const products = await Product.find();
  for (const prod of products) {
    let needsUpdate = false;
    for (const [key, value] of Object.entries(requiredFields)) {
      if (prod[key] === undefined) {
        prod[key] = value;
        needsUpdate = true;
      }
    }
    if (needsUpdate) {
      await prod.save();
      console.log(`Patched product ${prod.id}`);
    }
  }
  await mongoose.disconnect();
  console.log('All products patched.');
}

patchProducts();
