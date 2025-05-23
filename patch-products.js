// patch-products.js
const fs = require('fs');
const path = require('path');

const productsPath = path.join(__dirname, 'products.json');
const products = JSON.parse(fs.readFileSync(productsPath, 'utf8'));

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

const patched = products.map(prod => ({
  ...requiredFields,
  ...prod
}));

fs.writeFileSync(productsPath, JSON.stringify(patched, null, 2));
console.log('Patched all products with required fields.');
