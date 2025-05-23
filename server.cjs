require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');
const multer = require('multer');

const app = express();
const PORT = 4000;

app.use(cors());
app.use(bodyParser.json());

// MongoDB connection
const mongoURI = 'mongodb+srv://LEO:leo112944@cluster0.ye9exkm.mongodb.net/forvoqdb?retryWrites=true&w=majority&appName=Cluster0';
mongoose.connect(mongoURI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// Define Mongoose schemas and models

const paymentSchema = new mongoose.Schema({
  merchantId: String,
  amount: Number,
  id: String,
  date: String,
});

const Payment = mongoose.model('Payment', paymentSchema);

const userSchema = new mongoose.Schema({
  id: String,
  email: String,
  password: String,
  role: String,
  companyName: String,
});

const User = mongoose.model('User', userSchema);

const axios = require('axios');

// Order schema and model
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
  date: { type: String, default: '' }, // Store date as string YYYY-MM-DD
  time: { type: String, default: '' }, // Store time as string HH:mm:ss
  shippingLabelBase64: String, // Store base64 encoded PDF
});

const Order = mongoose.model('Order', orderSchema);

// Multer setup for file uploads
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + '-' + file.originalname);
  }
});

const upload = multer({ storage: storage });

// POST endpoint for file upload
app.post('/upload', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  // Optionally, save file metadata to MongoDB here
  res.status(201).json({ message: 'File uploaded successfully', filename: req.file.filename });
});

// POST endpoint to add a new user
app.post('/api/users', async (req, res) => {
  const userData = req.body;
  if (!userData.email || !userData.password || !userData.companyName) {
    return res.status(400).json({ error: 'Missing required user fields' });
  }
  try {
    // Check if user already exists
    const existingUser = await User.findOne({ email: userData.email });
    if (existingUser) {
      return res.status(409).json({ error: 'User with this email already exists' });
    }
    // Hash password before saving
    const hashedPassword = await bcrypt.hash(userData.password, 10);
    // Create new user
    const newUser = new User({
      id: `user-${Date.now()}`,
      role: userData.role || 'merchant',
      ...userData,
      password: hashedPassword,
    });
    await newUser.save();
    res.status(201).json(newUser);
  } catch (err) {
    console.error('Error creating user:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// GET endpoint to retrieve users
app.get('/api/users', async (req, res) => {
  try {
    const users = await User.find();
    res.json(users);
  } catch (err) {
    console.error('Error fetching users:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Example: GET endpoint for payments using MongoDB
app.get('/api/received-payments', async (req, res) => {
  try {
    const { merchantId } = req.query;
    let query = {};
    if (merchantId) {
      query.merchantId = merchantId;
    }
    const payments = await Payment.find(query).sort({ date: -1 });
    res.json(payments);
  } catch (err) {
    console.error('Error fetching payments:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Example: POST endpoint to add a received payment using MongoDB
app.post('/api/received-payments', async (req, res) => {
  const newPayment = req.body;
  if (!newPayment || !newPayment.merchantId || !newPayment.amount) {
    return res.status(400).json({ error: 'Invalid payment data' });
  }
  try {
    newPayment.id = Date.now().toString();
    newPayment.date = newPayment.date || new Date().toISOString().split('T')[0];
    const payment = new Payment(newPayment);
    await payment.save();
    res.status(201).json(payment);
  } catch (err) {
    console.error('Error saving payment:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

const ntpClient = require('ntp-client');

async function fetchISTDateTime() {
  return new Promise((resolve, reject) => {
    ntpClient.getNetworkTime("time.google.com", 123, function(err, date) {
      if(err) {
        console.error('Error fetching time from NTP server:', err);
        // Fallback to local IST calculation
        const now = new Date();
        const istOffset = 5.5 * 60; // IST offset in minutes
        const utc = now.getTime() + (now.getTimezoneOffset() * 60000);
        const istTime = new Date(utc + (istOffset * 60000));
        const dateStr = istTime.toISOString().substring(0, 10);
        const timeStr = istTime.toISOString().substring(11, 19);
        resolve({ date: dateStr, time: timeStr });
        return;
      }
      // Convert UTC time to IST (UTC+5:30)
      const utcTime = date.getTime();
      const istOffsetMs = 5.5 * 60 * 60 * 1000;
      const istDate = new Date(utcTime + istOffsetMs);
      const dateStr = istDate.toISOString().substring(0, 10);
      const timeStr = istDate.toISOString().substring(11, 19);
      resolve({ date: dateStr, time: timeStr });
    });
  });
}

app.post('/api/orders', async (req, res) => {
  const orderData = req.body;
  if (!orderData.id) {
    return res.status(400).json({ error: 'Order id is required' });
  }
  if (!orderData.date || !orderData.time) {
    const { date, time } = await fetchISTDateTime();
    orderData.date = date;
    orderData.time = time;
  }
  try {
    const existingOrder = await Order.findOne({ id: orderData.id });
    if (existingOrder) {
      return res.status(409).json({ error: 'Order with this id already exists' });
    }
    const newOrder = new Order(orderData);
    await newOrder.save();
    res.status(201).json(newOrder);
  } catch (err) {
    console.error('Error saving order:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// GET endpoint to retrieve orders
app.get('/api/orders', async (req, res) => {
  try {
    const orders = await Order.find().sort({ date: -1 });
    res.json(orders);
  } catch (err) {
    console.error('Error fetching orders:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// PUT endpoint to update an order by id
app.put('/api/orders/:id', async (req, res) => {
  const id = req.params.id;
  const updatedData = req.body;
  console.log(`PUT /api/orders/${id} called with data:`, updatedData);
  if (updatedData.id && updatedData.id !== id) {
    return res.status(400).json({ error: 'ID in URL and body do not match' });
  }
  try {
    const updatedOrder = await Order.findOneAndUpdate({ id }, updatedData, { new: true });
    if (!updatedOrder) {
      console.log(`Order with id ${id} not found`);
      return res.status(404).json({ error: 'Order not found' });
    }
    res.json(updatedOrder);
  } catch (err) {
    console.error('Error updating order:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Product schema and model
const Product = require('./models/Product');

// Inventory schema and model
const inventorySchema = new mongoose.Schema({
  id: String,
  productId: String,
  merchantId: String,
  quantity: Number,
  location: String,
  minStockLevel: Number,
  maxStockLevel: Number,
});
const Inventory = mongoose.model('Inventory', inventorySchema);

// Transaction schema and model
const transactionSchema = new mongoose.Schema({
  id: String,
  merchantId: String,
  orderId: String,
  productId: String,
  type: String,
  quantity: Number,
  notes: String,
  amount: Number,
  date: String,
});
const Transaction = mongoose.model('Transaction', transactionSchema);

// Inbound schema and model
const inboundSchema = new mongoose.Schema({
  id: String,
  merchantId: String,
  type: String,
  status: String,
  date: String,
  receivedDate: String,
  pickupDate: String,
  items: [
    {
      productId: String,
      quantity: Number,
      location: String,
    }
  ],
  pickupLocation: {
    buildingNumber: String,
    location: String,
    address: String,
    city: String,
    state: String,
    pincode: String,
    phone: String,
  },
  deliveryLocation: {
    buildingNumber: String,
    location: String,
    address: String,
    city: String,
    state: String,
    pincode: String,
    phone: String,
  },
  fee: Number,
});
const Inbound = mongoose.model('Inbound', inboundSchema);

// SavedPickupLocation schema and model
const savedPickupLocationSchema = new mongoose.Schema({
  id: String,
  merchantId: String,
  buildingNumber: String,
  location: String,
  address: String,
  city: String,
  state: String,
  pincode: String,
  phone: String,
});
const SavedPickupLocation = mongoose.model('SavedPickupLocation', savedPickupLocationSchema);

// CRUD endpoints for products
app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.find();
    res.json(products);
  } catch (err) {
    console.error('Error fetching products:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.post('/api/products', async (req, res) => {
  const productData = req.body;
  try {
    const newProduct = new Product(productData);
    await newProduct.save();
    res.status(201).json(newProduct);
  } catch (err) {
    console.error('Error saving product:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.put('/api/products/:id', async (req, res) => {
  const id = req.params.id;
  const updatedData = req.body;
  try {
    const updatedProduct = await Product.findOneAndUpdate({ id }, updatedData, { new: true });
    if (!updatedProduct) return res.status(404).json({ error: 'Product not found' });
    res.json(updatedProduct);
  } catch (err) {
    console.error('Error updating product:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.delete('/api/products/:id', async (req, res) => {
  const id = req.params.id;
  try {
    const deletedProduct = await Product.findOneAndDelete({ id });
    if (!deletedProduct) return res.status(404).json({ error: 'Product not found' });
    res.json({ message: 'Product deleted' });
  } catch (err) {
    console.error('Error deleting product:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// CRUD endpoints for inventory
app.get('/api/inventory', async (req, res) => {
  try {
    const inventory = await Inventory.find();
    res.json(inventory);
  } catch (err) {
    console.error('Error fetching inventory:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.post('/api/inventory', async (req, res) => {
  const inventoryData = req.body;
  try {
    const newInventory = new Inventory(inventoryData);
    await newInventory.save();
    res.status(201).json(newInventory);
  } catch (err) {
    console.error('Error saving inventory:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.put('/api/inventory/:id', async (req, res) => {
  const id = req.params.id;
  const updatedData = req.body;
  try {
    const updatedInventory = await Inventory.findOneAndUpdate({ id }, updatedData, { new: true });
    if (!updatedInventory) return res.status(404).json({ error: 'Inventory item not found' });
    res.json(updatedInventory);
  } catch (err) {
    console.error('Error updating inventory:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.delete('/api/inventory/:id', async (req, res) => {
  const id = req.params.id;
  try {
    const deletedInventory = await Inventory.findOneAndDelete({ id });
    if (!deletedInventory) return res.status(404).json({ error: 'Inventory item not found' });
    res.json({ message: 'Inventory item deleted' });
  } catch (err) {
    console.error('Error deleting inventory:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// CRUD endpoints for transactions
app.get('/api/transactions', async (req, res) => {
  try {
    const transactions = await Transaction.find();
    res.json(transactions);
  } catch (err) {
    console.error('Error fetching transactions:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.post('/api/transactions', async (req, res) => {
  const transactionData = req.body;
  try {
    const newTransaction = new Transaction(transactionData);
    await newTransaction.save();
    res.status(201).json(newTransaction);
  } catch (err) {
    console.error('Error saving transaction:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// CRUD endpoints for inbounds
app.get('/api/inbounds', async (req, res) => {
  try {
    const inbounds = await Inbound.find();
    res.json(inbounds);
  } catch (err) {
    console.error('Error fetching inbounds:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.post('/api/inbounds', async (req, res) => {
  const inboundData = req.body;
  try {
    // Ensure pickupLocation and deliveryLocation are objects, not strings
    if (typeof inboundData.pickupLocation === 'string') {
      inboundData.pickupLocation = null;
    }
    if (typeof inboundData.deliveryLocation === 'string') {
      inboundData.deliveryLocation = null;
    }
    const newInbound = new Inbound(inboundData);
    await newInbound.save();
    res.status(201).json(newInbound);
  } catch (err) {
    console.error('Error saving inbound:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.put('/api/inbounds/:id', async (req, res) => {
  const id = req.params.id;
  const updatedData = req.body;
  try {
    const updatedInbound = await Inbound.findOneAndUpdate({ id }, updatedData, { new: true });
    if (!updatedInbound) {
      return res.status(404).json({ error: 'Inbound not found' });
    }
    res.json(updatedInbound);
  } catch (err) {
    console.error('Error updating inbound:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// CRUD endpoints for savedPickupLocations
app.get('/api/savedPickupLocations', async (req, res) => {
  try {
    const locations = await SavedPickupLocation.find();
    res.json(locations);
  } catch (err) {
    console.error('Error fetching saved pickup locations:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.post('/api/savedPickupLocations', async (req, res) => {
  console.log('POST /api/savedPickupLocations body:', req.body);
  const {
    id,
    merchantId,
    buildingNumber,
    location,
    address,
    city,
    state,
    pincode,
    phone
  } = req.body;
  try {
    const newLocation = new SavedPickupLocation({
      id,
      merchantId,
      buildingNumber,
      location,
      address,
      city,
      state,
      pincode,
      phone
    });
    await newLocation.save();
    res.status(201).json(newLocation);
  } catch (err) {
    console.error('Error saving pickup location:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.put('/api/savedPickupLocations/:id', async (req, res) => {
  const id = req.params.id;
  console.log(`PUT /api/savedPickupLocations/${id} body:`, req.body);
  const {
    merchantId,
    buildingNumber,
    location,
    address,
    city,
    state,
    pincode,
    phone
  } = req.body;
  try {
    const updatedLocation = await SavedPickupLocation.findOneAndUpdate(
      { id },
      {
        merchantId,
        buildingNumber,
        location,
        address,
        city,
        state,
        pincode,
        phone
      },
      { new: true }
    );
    if (!updatedLocation) return res.status(404).json({ error: 'Pickup location not found' });
    res.json(updatedLocation);
  } catch (err) {
    console.error('Error updating pickup location:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.delete('/api/savedPickupLocations/:id', async (req, res) => {
  const id = req.params.id;
  try {
    const deletedLocation = await SavedPickupLocation.findOneAndDelete({ id });
    if (!deletedLocation) return res.status(404).json({ error: 'Pickup location not found' });
    res.json({ message: 'Pickup location deleted' });
  } catch (err) {
    console.error('Error deleting pickup location:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

const bcrypt = require('bcrypt');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

// In-memory OTP store: { userIdentifier: { otp: string, expiresAt: Date } }
const otpStore = {};

// Helper function to generate OTP
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString(); // 6 digit OTP
}

// Helper function to send OTP email (using Gmail SMTP)
async function sendOtpEmail(email, otp) {
  let transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.GMAIL_USER, // Your Gmail address
      pass: process.env.GMAIL_PASS, // Your Gmail app password or account password
    },
  });

  const mailOptions = {
    from: `"FORVOQ" <${process.env.GMAIL_USER}>`,
    to: email,
    subject: 'FORVOQ OTP Code – Complete Your Verification',
    text: `Hi there,\n\nWelcome to FORVOQ – your trusted partner in e-commerce fulfillment.\n\nTo proceed with your verification, please use the One-Time Password (OTP) below. This code is valid for the next 10 minutes.\n\n🔐 Your OTP Code: ${otp}\n\nIf you did not request this, please ignore this email. For your account’s security, do not share this code with anyone.\n\nNeed help? Reach out to our support team at forvoq@gmail.com or visit our Help Center.\n\nThank you for choosing FORVOQ.\n– The FORVOQ Team`,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`OTP ${otp} sent to email ${email}`);
  } catch (error) {
    console.error('Error sending OTP email:', error);
    throw error;
  }
}

// POST /api/forgot-password/request-otp
app.post('/api/forgot-password/request-otp', async (req, res) => {
  const { email, merchantId, phone } = req.body;
  if (!email && !merchantId && !phone) {
    return res.status(400).json({ error: 'Provide email, merchantId, or phone' });
  }
  try {
    // Find user by email or merchantId or phone
    let user;
    if (email) {
      user = await User.findOne({ email });
    }
    if (!user && merchantId) {
      user = await User.findOne({ id: merchantId });
    }
    if (!user && phone) {
      // Assuming phone is stored in User model, if not, adjust accordingly
      user = await User.findOne({ phone });
    }
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    const otp = generateOTP();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // OTP valid for 10 minutes
    otpStore[user.id] = { otp, expiresAt };
    await sendOtpEmail(user.email, otp);
    res.json({ message: 'OTP sent to registered email', userId: user.id });
  } catch (err) {
    console.error('Error in request-otp:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// POST /api/register/request-otp
app.post('/api/register/request-otp', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }
  try {
    const otp = generateOTP();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // OTP valid for 10 minutes
    otpStore[email] = { otp, expiresAt };
    await sendOtpEmail(email, otp);
    res.json({ message: 'OTP sent to email', email });
  } catch (err) {
    console.error('Error in register request-otp:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// POST /api/register/verify-otp
app.post('/api/register/verify-otp', (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) {
    return res.status(400).json({ error: 'Email and OTP are required' });
  }
  const record = otpStore[email];
  if (!record) {
    return res.status(400).json({ error: 'OTP not found or expired' });
  }
  if (record.expiresAt < new Date()) {
    delete otpStore[email];
    return res.status(400).json({ error: 'OTP expired' });
  }
  if (record.otp !== otp) {
    return res.status(400).json({ error: 'Invalid OTP' });
  }
  // OTP verified, delete it
  delete otpStore[email];
  res.json({ message: 'OTP verified' });
});

// POST /api/forgot-password/verify-otp
app.post('/api/forgot-password/verify-otp', (req, res) => {
  const { userId, otp } = req.body;
  if (!userId || !otp) {
    return res.status(400).json({ error: 'userId and otp are required' });
  }
  const record = otpStore[userId];
  if (!record) {
    return res.status(400).json({ error: 'OTP not found or expired' });
  }
  if (record.expiresAt < new Date()) {
    delete otpStore[userId];
    return res.status(400).json({ error: 'OTP expired' });
  }
  if (record.otp !== otp) {
    return res.status(400).json({ error: 'Invalid OTP' });
  }
  // OTP verified, delete it
  delete otpStore[userId];
  res.json({ message: 'OTP verified' });
});

// POST /api/forgot-password/reset-password
app.post('/api/forgot-password/reset-password', async (req, res) => {
  const { userId, newPassword } = req.body;
  if (!userId || !newPassword) {
    return res.status(400).json({ error: 'userId and newPassword are required' });
  }
  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    const updatedUser = await User.findOneAndUpdate(
      { id: userId },
      { password: hashedPassword },
      { new: true }
    );
    if (!updatedUser) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    console.error('Error in reset-password:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

const jwt = require('jsonwebtoken');


// POST /login endpoint
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  console.log('Login attempt for email:', email);
  if (!email || !password) {
    console.log('Missing email or password');
    return res.status(400).json({ error: 'Email and password are required' });
  }
  try {
    const user = await User.findOne({ email });
    if (!user) {
      console.log('User not found for email:', email);
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    const passwordMatch = await bcrypt.compare(password, user.password);
    console.log('Password match result:', passwordMatch);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    // Login successful - return user info (excluding password)
    const userInfo = {
      id: user.id,
      email: user.email,
      role: user.role,
      companyName: user.companyName,
    };
    res.json({ message: 'Login successful', user: userInfo });
  } catch (err) {
    console.error('Error during login:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Debug endpoint to get stored password hash for a user by email (for debugging only)
app.get('/debug/user-password', async (req, res) => {
  const email = req.query.email;
  if (!email) {
    return res.status(400).json({ error: 'Email query parameter is required' });
  }
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ email: user.email, passwordHash: user.password });
  } catch (err) {
    console.error('Error fetching user password hash:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
