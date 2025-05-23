const mongoose = require('mongoose');
const User = require('./models/User'); // Assuming you have a User model file
const Product = require('./models/Product'); // Assuming you have a Product model file
const Inventory = require('./models/Inventory'); // Assuming you have an Inventory model file
const Order = require('./models/Order'); // Assuming you have an Order model file

const mongoURI = 'mongodb+srv://LEO:leo112944@cluster0.ye9exkm.mongodb.net/forvoqdb?retryWrites=true&w=majority&appName=Cluster0';

const seed = async () => {
  try {
    await mongoose.connect(mongoURI);
    console.log('Connected to MongoDB for seeding');

    // Clear existing data
    await User.deleteMany({});
    await Product.deleteMany({});
    await Inventory.deleteMany({});
    await Order.deleteMany({});

    // Seed users
    const users = [
      { id: 'user-1', email: 'admin@example.com', password: 'admin123', role: 'admin', companyName: 'Admin Company' },
      { id: 'user-2', email: 'merchant@example.com', password: 'merchant123', role: 'merchant', companyName: 'Merchant Company' },
      { id: 'user-3', email: 'leo112944@gmail.com', password: 'pypyabcd', role: 'superadmin', companyName: 'FORVOQ' },
    ];
    await User.insertMany(users);

    // Seed products
    const products = [
      { id: 'prod-1', name: 'Product 1', merchantId: 'user-2', weightKg: 1, lengthCm: 10, breadthCm: 10, heightCm: 10, packingType: 'normal packing' },
      { id: 'prod-2', name: 'Product 2', merchantId: 'user-2', weightKg: 2, lengthCm: 20, breadthCm: 20, heightCm: 20, packingType: 'fragile packing' },
    ];
    await Product.insertMany(products);

    // Seed inventory
    const inventory = [
      { id: 'inv-1', productId: 'prod-1', merchantId: 'user-2', quantity: 100, location: 'Warehouse 1', minStockLevel: 10, maxStockLevel: 200 },
      { id: 'inv-2', productId: 'prod-2', merchantId: 'user-2', quantity: 50, location: 'Warehouse 1', minStockLevel: 5, maxStockLevel: 100 },
    ];
    await Inventory.insertMany(inventory);

    // Seed orders
    const orders = [
      {
        id: 'ord-1',
        merchantId: 'user-2',
        customerName: 'Customer A',
        address: '123 Main St, Springfield, IL 62704',
        city: 'Springfield',
        state: 'IL',
        pincode: '62704',
        phone: '1234567890',
        items: [
          { productId: 'prod-1', name: 'Product 1', quantity: 2 },
          { productId: 'prod-2', name: 'Product 2', quantity: 1 },
        ],
        status: 'pending',
        date: new Date().toISOString().split('T')[0],
      },
    ];
    await Order.insertMany(orders);

    console.log('Seeding completed');
    process.exit(0);
  } catch (error) {
    console.error('Error seeding data:', error);
    process.exit(1);
  }
};

seed();
