require('dotenv').config();

// WARNING: Storing credentials in source is insecure. These values are set for local testing only.
// Recommended: use environment variables or a secrets manager in production.
process.env.GMAIL_USER = process.env.GMAIL_USER || 'forvoq@gmail.com';
process.env.GMAIL_PASS = process.env.GMAIL_PASS || 'awgruswxpbrmvooz';
// Admin upload secret (hardcoded by request).
// WARNING: Hardcoding secrets is insecure. Do not commit this file to public repos.
const ADMIN_UPLOAD_SECRET = '011225';
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');
const multer = require('multer');
const crypto = require("crypto");

const app = express();
const PORT = 4000;

// CORS setup to explicitly allow all methods
app.use(cors({
  origin: ['https://app.forvoq.com','http://localhost:5173'], // Updated for production
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  // Allow the admin upload secret header so frontend can call protected admin endpoints
  allowedHeaders: ['Content-Type', 'Authorization', 'x-admin-upload-secret'],
  credentials: true
}));
// Capture raw request body for webhook HMAC verification while keeping
// JSON parsing for normal routes.
app.use(bodyParser.json({
  verify: function (req, res, buf) {
    try {
      req.rawBody = buf;
    } catch (e) {
      req.rawBody = null;
    }
  }
}));

// Debug helper: log presence of admin header for admin routes (masked)
app.use('/api/admin', (req, res, next) => {
  try {
    const provided = req.get('x-admin-upload-secret') || '';
    const masked = provided ? (provided.length > 2 ? `${provided[0]}***${provided.slice(-1)}` : '***') : '<none>';
    console.log(`/api/admin request - x-admin-upload-secret: ${masked} - ${req.method} ${req.path}`);
  } catch (e) {}
  next();
});

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

// Webhook schema and model
const webhookSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  merchantId: String,
  topic: String,
  address: String,
  format: { type: String, default: 'json' },
  shopifyDomain: String,
  signature: String,
  active: { type: Boolean, default: true },
  createdAt: { type: String, default: () => new Date().toISOString() }
}, { strict: false });

const Webhook = mongoose.model('Webhook', webhookSchema);

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
  // Tracking code for courier
  trackingCode: { type: String, default: '' },
  status: String,
  date: { type: String, default: '' }, // Store date as string YYYY-MM-DD
  time: { type: String, default: '' }, // Store time as string HH:mm:ss
  // Timestamps for lifecycle events (ISO strings)
  packedAt: { type: String, default: '' },
  dispatchedAt: { type: String, default: '' },
  deliveredAt: { type: String, default: '' },
  // Courier/delivery partner name provided at creation or edit
  deliveryPartner: { type: String, default: '' },
  // Source of the order creation (e.g., 'manual' when merchant uses Add Order form)
  source: { type: String, default: null },
  shippingLabelBase64: String, // Store base64 encoded PDF
}, { strict: false }); // Allow extra fields in case of backwards compatibility

// Index to prevent duplicate Shopify webhook processing (sparse + unique)
orderSchema.index(
  { shopifyWebhookId: 1 },
  { unique: true, sparse: true }
);

const Order = mongoose.model('Order', orderSchema);

// PackingFee schema and model - stores per-order packing breakdown
const packingFeeSchema = new mongoose.Schema({
  orderId: { type: String, required: true, unique: true },
  merchantId: String,
  items: [
    {
      productId: String,
      name: String,
      quantity: Number,
      warehousingPerItem: Number,
      transportationPerItem: Number,
      itemPackingPerItem: Number,
      estimatedTotalPerItem: Number,
      lineTotal: Number
    }
  ],
  trackingFee: { type: Number, default: 3 },
  boxFee: { type: Number, default: 0 },
  boxCutting: { type: Boolean, default: false },
  totalPackingFee: { type: Number, default: 0 },
  totalWeightKg: { type: Number, default: 0 },
  updatedAt: { type: String, default: '' }
}, { strict: false });

const PackingFee = mongoose.model('PackingFee', packingFeeSchema);

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

// Admin restore endpoint: accepts a zip file containing JSON files per collection.
// It will skip restoring the `users` collection and any keys matching the preserve regex.
app.post('/api/admin/restore-zip', upload.single('file'), async (req, res) => {
  try {
    // simple auth: check secret header
    let provided = req.get('x-admin-upload-secret') || '';
    provided = String(provided).trim();
    const expected = String(ADMIN_UPLOAD_SECRET || '').trim();
    if (!expected || !provided || provided !== expected) {
      // Log masked values and lengths for debugging without revealing full secret
      const mask = (s) => s ? (s.length > 2 ? `${s[0]}***${s.slice(-1)}` : '***') : '<none>';
      console.log('/api/admin/restore-zip auth failed - provided:', mask(provided), `len=${provided.length}`, 'expected:', mask(expected), `len=${expected.length}`);
      return res.status(403).json({ error: 'Forbidden: invalid admin upload secret' });
    }

    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    // Log upload info for debugging
    console.log('/api/admin/restore-zip called by', req.ip, 'uploaded file:', req.file && req.file.filename);
    const JSZip = require('jszip');
    const buffer = require('fs').readFileSync(req.file.path);
    const zip = await JSZip.loadAsync(buffer);
    // List zip contents for debugging
    try {
      const fileNames = Object.keys(zip.files);
      console.log('Uploaded zip contains files:', fileNames);
    } catch (zerr) {
      console.warn('Could not list zip contents', zerr && zerr.message);
    }

    // Map file key names to mongoose models available in this file
    const modelMap = {
      products: Product,
      inventory: Inventory,
      transactions: Transaction,
      orders: Order,
      inbounds: Inbound,
      users: User,
      savedPickupLocations: SavedPickupLocation,
      payments: Payment,
      packingFees: PackingFee,
      shippingTemplates: ShippingTemplate
    };

    const preserveRegex = /user|auth|session|currentUser|token/i;
    const results = { restored: [], skipped: [], errors: [] };

    const entries = Object.keys(zip.files).filter(n => n.endsWith('.json'));
    for (const name of entries) {
      try {
        const content = await zip.file(name).async('string');
        const parts = name.split('/');
        const filename = parts[parts.length - 1];
        const key = filename.replace(/\.json$/i, '');

        if (key === 'users' || preserveRegex.test(key)) {
          results.skipped.push(key);
          continue;
        }

        let parsed;
        try { parsed = JSON.parse(content); } catch (e) { parsed = null; }
        if (!parsed) {
          results.errors.push({ key, error: 'Invalid JSON' });
          continue;
        }

        const Model = modelMap[key];
        if (!Model) {
          // unknown key: save to uploads folder as a JSON file for manual inspection
          const outPath = path.join(uploadDir, `${Date.now()}-${filename}`);
          fs.writeFileSync(outPath, JSON.stringify(parsed, null, 2));
          results.restored.push({ key, note: 'saved-to-uploads' });
          continue;
        }

        // Replace collection contents: remove existing docs then insert provided docs
        if (Array.isArray(parsed)) {
          await Model.deleteMany({});
          if (parsed.length > 0) {
            await Model.insertMany(parsed, { ordered: false });
          }
          results.restored.push(key);
        } else if (typeof parsed === 'object') {
          // If object with keys, attempt to insert as single doc after clearing
          await Model.deleteMany({});
          await Model.create(parsed);
          results.restored.push(key);
        } else {
          results.errors.push({ key, error: 'Unsupported JSON shape' });
        }
      } catch (err) {
        console.error('Restore entry error', name, err);
        results.errors.push({ name, error: err.message });
      }
    }

    // cleanup uploaded temp file
    try { fs.unlinkSync(req.file.path); } catch (e) {}

    return res.json({ message: 'Restore processed', results });
  } catch (err) {
    console.error('Restore zip error:', err && (err.stack || err));
    // In development return stack for debugging; in production remove stack exposure
    return res.status(500).json({ error: 'Restore failed', details: err.message, stack: err.stack });
  }
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
      id: userData.role === 'admin' ? 'admin-' + Date.now() : `user-${Date.now()}`,
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

// GET endpoint to retrieve a user by id
app.get('/api/users/:id', async (req, res) => {
  const id = req.params.id;
  try {
    const user = await User.findOne({ id });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (err) {
    console.error('Error fetching user by id:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// --- Webhook endpoints ---

// Get all webhooks (admin)
app.get('/api/webhooks', async (req, res) => {
  try {
    console.log('GET /api/webhooks called');
    const list = await Webhook.find().sort({ createdAt: -1 });
    return res.json(list);
  } catch (err) {
    console.error('Error fetching webhooks:', err && (err.stack || err));
    // Return empty list on error so frontend table can render gracefully.
    return res.json([]);
  }
});

// Get webhooks for a merchant
app.get('/api/merchants/:id/webhooks', async (req, res) => {
  try {
    const id = req.params.id;
    console.log(`/api/merchants/${id}/webhooks called - returning all webhooks`);
    // Return all webhooks so the admin UI always shows full data set.
    const list = await Webhook.find().sort({ createdAt: -1 });
    return res.json(list);
  } catch (err) {
    console.error('Error fetching merchant webhooks:', err && (err.stack || err));
    // Return empty list on error so frontend shows no webhooks instead of failing.
    return res.json([]);
  }
});

// Create webhook for merchant
app.post('/api/merchants/:id/webhooks', async (req, res) => {
  try {
    const mId = req.params.id;
    const body = req.body || {};
    console.log('/api/merchants/:id/webhooks - payload:', JSON.stringify(body));
    const newWh = new Webhook({
      id: `wh-${Date.now()}`,
      merchantId: mId,
      topic: body.topic || 'orders/create',
      address: body.address || '',
      format: body.format || 'json',
      shopifyDomain: body.shopifyDomain || '',
      signature: body.signature || '',
      active: body.active !== undefined ? body.active : true,
      createdAt: new Date().toISOString()
    });
    try {
      const saved = await newWh.save();
      console.log('Webhook saved:', saved.id || saved._id);
      return res.status(201).json(saved);
    } catch (saveErr) {
      console.error('Error saving webhook to DB:', saveErr && (saveErr.stack || saveErr.message));
      return res.status(500).json({ error: 'Failed to save webhook', details: saveErr && saveErr.message });
    }
  } catch (err) {
    console.error('Error creating webhook:', err);
    return res.status(500).json({ error: 'Internal Server Error', details: err.message });
  }
});

// Create global webhook (no merchant)
app.post('/api/webhooks', async (req, res) => {
  try {
    const body = req.body || {};
    console.log('/api/webhooks - payload:', JSON.stringify(body));
    const newWh = new Webhook({
      id: `wh-${Date.now()}`,
      merchantId: body.merchantId || '',
      topic: body.topic || 'orders/create',
      address: body.address || '',
      format: body.format || 'json',
      shopifyDomain: body.shopifyDomain || '',
      signature: body.signature || '',
      active: body.active !== undefined ? body.active : true,
      createdAt: new Date().toISOString()
    });
    try {
      const saved = await newWh.save();
      console.log('Global webhook saved:', saved.id || saved._id);
      return res.status(201).json(saved);
    } catch (saveErr) {
      console.error('Error saving global webhook to DB:', saveErr && (saveErr.stack || saveErr.message));
      return res.status(500).json({ error: 'Failed to save webhook', details: saveErr && saveErr.message });
    }
  } catch (err) {
    console.error('Error creating webhook:', err);
    return res.status(500).json({ error: 'Internal Server Error', details: err.message });
  }
});

// Delete a merchant webhook
app.delete('/api/merchants/:id/webhooks/:wid', async (req, res) => {
  try {
    const { id, wid } = req.params;
    const deleted = await Webhook.findOneAndDelete({ id: wid, merchantId: id });
    if (!deleted) return res.status(404).json({ error: 'Webhook not found' });
    return res.json({ message: 'Webhook deleted' });
  } catch (err) {
    console.error('Error deleting merchant webhook:', err);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Delete global webhook by id
app.delete('/api/webhooks/:id', async (req, res) => {
  try {
    const wid = req.params.id;
    const deleted = await Webhook.findOneAndDelete({ id: wid });
    if (!deleted) return res.status(404).json({ error: 'Webhook not found' });
    return res.json({ message: 'Webhook deleted' });
  } catch (err) {
    console.error('Error deleting webhook:', err);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Update global webhook by id
app.patch('/api/webhooks/:id', async (req, res) => {
  try {
    const wid = req.params.id;
    const update = req.body || {};
    // Prevent changing the primary generated id
    delete update.id;
    const updated = await Webhook.findOneAndUpdate({ id: wid }, { $set: update }, { new: true });
    if (!updated) return res.status(404).json({ error: 'Webhook not found' });
    return res.json(updated);
  } catch (err) {
    console.error('Error updating webhook:', err && (err.stack || err));
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Update merchant-scoped webhook
app.patch('/api/merchants/:id/webhooks/:wid', async (req, res) => {
  try {
    const { id, wid } = req.params;
    const update = req.body || {};
    delete update.id;
    const updated = await Webhook.findOneAndUpdate({ id: wid, merchantId: id }, { $set: update }, { new: true });
    if (!updated) return res.status(404).json({ error: 'Webhook not found' });
    return res.json(updated);
  } catch (err) {
    console.error('Error updating merchant webhook:', err && (err.stack || err));
    return res.status(500).json({ error: 'Internal Server Error' });
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

// Google Drive server-side upload support
// Uses a Service Account JSON which must be provided via environment variable
// Do NOT commit service account keys to source control. Set the env var in production.
let google;
try {
  google = require('googleapis').google;
} catch (e) {
  console.warn('googleapis not installed; server-side Drive upload endpoint will be unavailable. Run `npm install` in backend.');
}

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
  console.log('POST /api/orders - Received order data:', JSON.stringify(orderData, null, 2));
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
    
    // Explicitly ensure all fields are present with defaults
    const completeOrderData = {
      id: orderData.id,
      merchantId: orderData.merchantId,
      customerName: orderData.customerName || '',
      address: orderData.address || '',
      city: orderData.city || '',
      state: orderData.state || '',
      pincode: orderData.pincode || '',
      phone: orderData.phone || '',
      items: orderData.items || [],
      status: orderData.status || 'pending',
      date: orderData.date || '',
      time: orderData.time || '',
      packedAt: orderData.packedAt || '',
      dispatchedAt: orderData.dispatchedAt || '',
      deliveredAt: orderData.deliveredAt || '',
      deliveryPartner: orderData.deliveryPartner || '',
      shippingLabelBase64: orderData.shippingLabelBase64 || '',
        trackingCode: orderData.trackingCode !== undefined ? orderData.trackingCode : '',
      // Record source if provided (e.g., 'manual' for merchant manual entry)
      source: orderData.source !== undefined ? orderData.source : null,
      // Accept packedweight if provided (allows storing frontend-entered packed weight)
      packedweight: orderData.packedweight !== undefined ? orderData.packedweight : (orderData.totalWeightKg || ''),
    };
    
    console.log('POST /api/orders - Complete order data to save:', JSON.stringify(completeOrderData, null, 2));
    
    const newOrder = new Order(completeOrderData);
    const savedOrder = await newOrder.save();
    console.log('POST /api/orders - Saved order to DB:', JSON.stringify(savedOrder.toObject(), null, 2));
    
    // Verify the saved document includes all fields
    const verifyOrder = await Order.findOne({ id: orderData.id });
    console.log('POST /api/orders - Verification from DB:', JSON.stringify(verifyOrder.toObject(), null, 2));
    // Defensive: if client provided a source but it wasn't persisted for some reason,
    // explicitly set it and fetch the authoritative copy again.
    if ((verifyOrder.source === undefined || verifyOrder.source === null) && orderData.source !== undefined) {
      try {
        console.log('POST /api/orders - Source missing in DB, forcing source:', orderData.source);
        const forced = await Order.findOneAndUpdate({ id: orderData.id }, { $set: { source: orderData.source } }, { new: true });
        if (forced) {
          console.log('POST /api/orders - Forced source persisted, updated doc:', JSON.stringify(forced.toObject(), null, 2));
        }
      } catch (e) {
        console.error('POST /api/orders - Failed to force-persist source:', e);
      }
    }
    
    res.status(201).json(verifyOrder);
  } catch (err) {
    console.error('Error saving order:', err);
    res.status(500).json({ error: 'Internal Server Error', details: err.message });
  }
});

/**
 * Server-side endpoint to upload a backup JSON to an application-owned Google Drive
 * Security: requires header `x-admin-upload-secret` to match `process.env.ADMIN_UPLOAD_SECRET`.
 * The service account credentials JSON must be available in `process.env.GOOGLE_SERVICE_ACCOUNT_JSON`.
 * Request body: { filename?: string, backup: <object> }
 */
app.post('/api/admin/backup-upload', async (req, res) => {
  try {
    // simple auth: check secret header
    let provided = req.get('x-admin-upload-secret') || '';
    provided = String(provided).trim();
    const expected = String(ADMIN_UPLOAD_SECRET || '').trim();
    if (!expected || !provided || provided !== expected) {
      const mask = (s) => s ? (s.length > 2 ? `${s[0]}***${s.slice(-1)}` : '***') : '<none>';
      console.log('/api/admin/backup-upload auth failed - provided:', mask(provided), `len=${provided.length}`, 'expected:', mask(expected), `len=${expected.length}`);
      return res.status(403).json({ error: 'Forbidden: invalid admin upload secret' });
    }

    if (!google) return res.status(500).json({ error: 'Server not configured for Drive uploads (googleapis missing)' });

    const saJson = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;
    if (!saJson) return res.status(500).json({ error: 'Server misconfigured: missing GOOGLE_SERVICE_ACCOUNT_JSON' });

    let credentials;
    try {
      credentials = typeof saJson === 'string' ? JSON.parse(saJson) : saJson;
    } catch (e) {
      console.error('Invalid GOOGLE_SERVICE_ACCOUNT_JSON:', e);
      return res.status(500).json({ error: 'Invalid service account JSON' });
    }

    const auth = new google.auth.GoogleAuth({
      credentials,
      scopes: ['https://www.googleapis.com/auth/drive.file']
    });

    const drive = google.drive({ version: 'v3', auth });

    const payload = req.body && req.body.backup ? req.body.backup : req.body;
    if (!payload || (typeof payload === 'object' && Object.keys(payload).length === 0)) {
      return res.status(400).json({ error: 'No backup payload provided' });
    }

    const jsonString = JSON.stringify(payload, null, 2);
    const buffer = Buffer.from(jsonString, 'utf8');
    const filename = req.body && req.body.filename ? String(req.body.filename) : `forvoq_backup_${new Date().toISOString().replace(/[:.]/g,'-')}.json`;

    // Create file on Drive
    const stream = require('stream');
    const readable = new stream.Readable();
    readable._read = () => {}; // _read is required but you can noop it
    readable.push(buffer);
    readable.push(null);

    const response = await drive.files.create({
      requestBody: { name: filename, mimeType: 'application/json' },
      media: { mimeType: 'application/json', body: readable },
      fields: 'id, name'
    });

    return res.status(201).json({ message: 'Backup uploaded to Drive', file: response.data });
  } catch (err) {
    console.error('Backup upload error:', err);
    return res.status(500).json({ error: 'Failed to upload backup', details: err.message });
  }
});

// Admin export endpoint: returns all main collections as a single JSON object
app.get('/api/admin/export-all', async (req, res) => {
  try {
    let provided = req.get('x-admin-upload-secret') || '';
    provided = String(provided).trim();
    const expected = String(ADMIN_UPLOAD_SECRET || '').trim();
    if (!expected || !provided || provided !== expected) {
      const mask = (s) => s ? (s.length > 2 ? `${s[0]}***${s.slice(-1)}` : '***') : '<none>';
      console.log('/api/admin/export-all auth failed - provided:', mask(provided), `len=${provided.length}`, 'expected:', mask(expected), `len=${expected.length}`);
      return res.status(403).json({ error: 'Forbidden: invalid admin upload secret' });
    }

    const [products, inventory, transactions, orders, inbounds, users, locations, payments, packingFees, shippingTemplates] = await Promise.all([
      Product.find().lean(),
      Inventory.find().lean(),
      Transaction.find().lean(),
      Order.find().lean(),
      Inbound.find().lean(),
      User.find().lean(),
      SavedPickupLocation.find().lean(),
      Payment.find().lean(),
      PackingFee.find().lean(),
      ShippingTemplate.find().lean()
    ]);

    const exportObj = {
      products,
      inventory,
      transactions,
      orders,
      inbounds,
      users,
      savedPickupLocations: locations,
      payments,
      packingFees,
      shippingTemplates,
      exportedAt: new Date().toISOString()
    };

    return res.json(exportObj);
  } catch (err) {
    console.error('Export all error:', err);
    return res.status(500).json({ error: 'Failed to export data', details: err.message });
  }
});

// GET endpoint to retrieve orders
app.get('/api/orders', async (req, res) => {
  try {
    // Use aggregation to join packingfees so frontend gets server-authoritative totalPackingFee
    const orders = await Order.aggregate([
      { $sort: { date: -1 } },
      { $lookup: {
          from: 'packingfees',
          localField: 'id',
          foreignField: 'orderId',
          as: 'pf'
      } },
      { $addFields: {
          pf0: { $arrayElemAt: ['$pf', 0] }
      } },
      { $addFields: {
          packingFee: { $cond: [{ $ifNull: ['$pf0.totalPackingFee', false] }, '$pf0.totalPackingFee', '$packingFee'] },
          packingDetails: { $cond: [{ $ifNull: ['$pf0.items', false] }, '$pf0.items', '$packingDetails'] }
      } },
      { $project: { pf: 0, pf0: 0 } }
    ]).exec();
    res.json(orders);
  } catch (err) {
    console.error('Error fetching orders:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// DEBUG: Get a specific order by ID to check all fields
app.get('/api/orders-debug/:id', async (req, res) => {
  const id = req.params.id;
  try {
    const order = await Order.findOne({ id });
    if (!order) {
      return res.status(404).json({ error: 'Order not found', searchedId: id });
    }
    const orderObj = order.toObject();
    console.log(`DEBUG: Order ${id} from MongoDB:`, JSON.stringify(orderObj, null, 2));
    res.json({
      message: 'Order found',
      order: orderObj,
      deliveryPartnerExists: 'deliveryPartner' in orderObj,
      deliveryPartnerValue: orderObj.deliveryPartner,
      allKeys: Object.keys(orderObj)
    });
  } catch (err) {
    console.error(`Error fetching debug order ${id}:`, err);
    res.status(500).json({ error: 'Internal Server Error', details: err.message });
  }
});

// PUT endpoint to update an order by id
app.put('/api/orders/:id', async (req, res) => {
  const id = req.params.id;
  const updatedData = req.body;
  console.log(`PUT /api/orders/${id} called with data:`, JSON.stringify(updatedData, null, 2));

  if (updatedData.id && updatedData.id !== id) {
    return res.status(400).json({ error: 'ID in URL and body do not match' });
  }

  try {
    // Fetch the existing order
    const existingOrder = await Order.findOne({ id });
    if (!existingOrder) {
      console.log(`Order with id ${id} not found`);
      return res.status(404).json({ error: 'Order not found' });
    }

    console.log(`PUT /api/orders/${id} - Existing order before update:`, JSON.stringify(existingOrder.toObject(), null, 2));

    // Update the order fields. Use explicit undefined checks so falsy but present values are saved.
    if (updatedData.trackingCode !== undefined) existingOrder.trackingCode = updatedData.trackingCode;
    if (updatedData.customerName !== undefined) existingOrder.customerName = updatedData.customerName;
    if (updatedData.address !== undefined) existingOrder.address = updatedData.address;
    if (updatedData.city !== undefined) existingOrder.city = updatedData.city;
    if (updatedData.state !== undefined) existingOrder.state = updatedData.state;
    if (updatedData.pincode !== undefined) existingOrder.pincode = updatedData.pincode;
    if (updatedData.phone !== undefined) existingOrder.phone = updatedData.phone;
    if (updatedData.deliveryPartner !== undefined) existingOrder.deliveryPartner = updatedData.deliveryPartner;
    if (updatedData.source !== undefined) existingOrder.source = updatedData.source;
    if (updatedData.status !== undefined) existingOrder.status = updatedData.status;
    if (updatedData.items !== undefined) existingOrder.items = updatedData.items;
    // Persist total weight and packed timestamp if provided (allow zero values)
    if (updatedData.totalWeightKg !== undefined) existingOrder.totalWeightKg = updatedData.totalWeightKg;
    // Persist packedweight if provided
    if (updatedData.packedweight !== undefined) existingOrder.packedweight = updatedData.packedweight;
    if (updatedData.packedAt !== undefined) existingOrder.packedAt = updatedData.packedAt;
    // Persist dispatch/delivery timestamps if provided
    if (updatedData.dispatchedAt !== undefined) {
      console.log(`PUT /api/orders/${id} - received dispatchedAt:`, updatedData.dispatchedAt, typeof updatedData.dispatchedAt);
      existingOrder.dispatchedAt = updatedData.dispatchedAt;
      console.log(`PUT /api/orders/${id} - existingOrder.dispatchedAt after set:`, existingOrder.dispatchedAt);
    }
    if (updatedData.dispatchDate !== undefined) {
      console.log(`PUT /api/orders/${id} - received dispatchDate:`, updatedData.dispatchDate);
      existingOrder.dispatchDate = updatedData.dispatchDate;
    }
    if (updatedData.deliveredAt !== undefined) {
      console.log(`PUT /api/orders/${id} - received deliveredAt:`, updatedData.deliveredAt);
      existingOrder.deliveredAt = updatedData.deliveredAt;
    }
    // Persist box fee and box cutting options
    if (updatedData.boxFee !== undefined) {
      existingOrder.boxFee = Number(updatedData.boxFee);
    }
    if (updatedData.boxCutting !== undefined) {
      existingOrder.boxCutting = Boolean(updatedData.boxCutting);
    }
    // Persist trackingFee: use provided value if present, otherwise default to 3
    if (updatedData.trackingFee !== undefined) {
      existingOrder.trackingFee = Number(updatedData.trackingFee);
    } else {
      // Ensure there is always a trackingFee stored on the order; default to 3
      existingOrder.trackingFee = 3;
    }
    // Persist packingFee if provided (total of item-level fees + box/tracking calculation)
    if (updatedData.packingFee !== undefined) {
      existingOrder.packingFee = Number(updatedData.packingFee);
    }
    // Persist packingDetails array if provided by the client
    if (updatedData.packingDetails !== undefined) {
      existingOrder.packingDetails = updatedData.packingDetails;
    }

    // Defensive normalization: coerce numeric fields on items and compute
    // total weights from per-item weights when the client didn't provide them.
    try {
      // Ensure items array exists on the order
      existingOrder.items = Array.isArray(existingOrder.items) ? existingOrder.items : (updatedData.items || []);

      // Coerce per-item numeric fields and compute total weight from items
      let totalFromItems = 0;
      for (let it of existingOrder.items) {
        if (!it) continue;
        if (it.quantity !== undefined) it.quantity = Number(it.quantity) || 0;
        if (it.weightPerItemKg !== undefined) it.weightPerItemKg = Number(it.weightPerItemKg) || 0;
        if (it.weightKg !== undefined) it.weightKg = Number(it.weightKg) || 0;

        const perItem = (it.weightPerItemKg !== undefined && it.weightPerItemKg !== null && !Number.isNaN(it.weightPerItemKg))
          ? it.weightPerItemKg
          : ((it.weightKg !== undefined && it.weightKg !== null && !Number.isNaN(it.weightKg)) ? it.weightKg : 0);

        totalFromItems += (Number(it.quantity) || 0) * (Number(perItem) || 0);
      }

      // Use client-provided totalWeightKg if present, otherwise computed value
      if (updatedData.totalWeightKg !== undefined) {
        existingOrder.totalWeightKg = Number(updatedData.totalWeightKg) || 0;
      } else {
        existingOrder.totalWeightKg = totalFromItems;
      }

      // Use client-provided packedweight if present, otherwise computed value
      if (updatedData.packedweight !== undefined) {
        existingOrder.packedweight = Number(updatedData.packedweight) || 0;
      } else {
        existingOrder.packedweight = totalFromItems;
      }
    } catch (normErr) {
      console.warn(`PUT /api/orders/${id} - normalization error:`, normErr && (normErr.stack || normErr.message));
    }

    console.log(`PUT /api/orders/${id} - Fields after applying updates:`, JSON.stringify({
      trackingCode: existingOrder.trackingCode,
      totalWeightKg: existingOrder.totalWeightKg,
      packedAt: existingOrder.packedAt,
      status: existingOrder.status,
      packedweight: existingOrder.packedweight
    }, null, 2));

    // Save the updated order
    let savedOrder = await existingOrder.save();
    console.log(`PUT /api/orders/${id} - Updated order saved (initial save):`, JSON.stringify(savedOrder.toObject(), null, 2));

    // Server-authoritative: when order is packed, compute per-item components and upsert PackingFee
    try {
      const shouldComputePacking = (String(savedOrder.status || '').toLowerCase() === 'packed') || (updatedData.packingFee !== undefined);
      if (shouldComputePacking) {
        // helpers
        const calculateVolumetricWeight = (length, width, height) => {
          const l = Number(length) || 0; const w = Number(width) || 0; const h = Number(height) || 0;
          if (!l || !w || !h) return 0;
          return (l * w * h) / 5000;
        };
        const calculateDispatchFee = (actualWeight, volumetricWeight, packingType) => {
          const weight = Math.max(Number(actualWeight) || 0, Number(volumetricWeight) || 0);
          let baseFee = 7;
          let additionalFeePerHalfKg = 2;
          switch ((packingType || '').toLowerCase()) {
            case 'fragile packing': baseFee = 11; additionalFeePerHalfKg = 4; break;
            case 'eco friendly fragile packing': baseFee = 12; additionalFeePerHalfKg = 5; break;
            case 'normal packing':
            default: baseFee = 7; additionalFeePerHalfKg = 2; break;
          }
          if (weight <= 0.5) return baseFee;
          const additionalUnits = Math.ceil((weight - 0.5) / 0.5);
          return baseFee + additionalUnits * additionalFeePerHalfKg;
        };

        const items = savedOrder.items || [];
        let itemsPackingTotal = 0;
        const pfItems = [];
        for (const it of items) {
          try {
            let prod = null;
            if (it && it.productId) {
              prod = await Product.findOne({ id: it.productId });
              if (!prod) {
                try { prod = await Product.findById(it.productId); } catch (e) { prod = null; }
              }
            }
            prod = prod || {};
            const actual = Number(prod.weightKg || it.weightPerItemKg || 0);
            const vol = calculateVolumetricWeight(prod.lengthCm || 0, prod.breadthCm || 0, prod.heightCm || 0);
            const packing = (prod.itemPackingFee !== undefined && prod.itemPackingFee !== null && prod.itemPackingFee !== '')
              ? Number(prod.itemPackingFee) || 0
              : calculateDispatchFee(actual, vol, prod.packingType || 'normal packing');
            const transportation = Number(prod.transportationFee || 0);
            const warehousing = Number(prod.warehousingRatePerKg || 0) * (Number(prod.weightKg || actual || 0));
            const perItemTotal = Number((packing + transportation + warehousing).toFixed(2));
            const qty = Number(it.quantity || 0);
            const lineTotal = Number((perItemTotal * qty).toFixed(2));
            itemsPackingTotal += lineTotal;
            pfItems.push({
              productId: it.productId || '',
              name: it.name || prod.name || '',
              quantity: qty,
              warehousingPerItem: Number(warehousing.toFixed(2)),
              transportationPerItem: Number(transportation.toFixed(2)),
              itemPackingPerItem: Number(packing.toFixed(2)),
              estimatedTotalPerItem: perItemTotal,
              lineTotal
            });
          } catch (innerErr) {
            console.error('Error computing item fees for order', id, it, innerErr);
          }
        }

          const boxFee = Number((updatedData.boxFee !== undefined ? updatedData.boxFee : savedOrder.boxFee) || 0);
          const boxCutting = Boolean((updatedData.boxCutting !== undefined ? updatedData.boxCutting : savedOrder.boxCutting) || false);
          const boxCuttingCharge = boxCutting ? 1 : 0;
          const trackingFee = Number((updatedData.trackingFee !== undefined ? updatedData.trackingFee : (savedOrder.trackingFee !== undefined ? savedOrder.trackingFee : 3)) || 3);
          const totalPackingFee = Number((itemsPackingTotal + boxFee + boxCuttingCharge + trackingFee).toFixed(2));

        // Recompute authoritative total weight from savedOrder.items to ensure
        // server-side totalWeightKg / packedweight reflect per-item weights
        let computedTotalWeight = 0;
        try {
          const sItems = Array.isArray(savedOrder.items) ? savedOrder.items : [];
          for (const iti of sItems) {
            if (!iti) continue;
            const qtyi = Number(iti.quantity || 0) || 0;
            const perItemWeight = (iti.weightPerItemKg !== undefined && iti.weightPerItemKg !== null && !Number.isNaN(iti.weightPerItemKg))
              ? Number(iti.weightPerItemKg)
              : ((iti.weightKg !== undefined && iti.weightKg !== null && !Number.isNaN(iti.weightKg)) ? Number(iti.weightKg) : 0);
            computedTotalWeight += qtyi * (perItemWeight || 0);
          }
        } catch (wErr) {
          console.warn('Error recomputing total weight from items for order', id, wErr && (wErr.stack || wErr.message));
        }

        // Decide final authoritative weight. If client provided `packedweight`, prefer that
        // (the admin-entered value). Otherwise, use computedTotalWeight from per-item weights.
        const clientPacked = (updatedData && Object.prototype.hasOwnProperty.call(updatedData, 'packedweight')) ? Number(updatedData.packedweight || 0) : undefined;
        const finalWeight = (clientPacked !== undefined && !Number.isNaN(clientPacked)) ? clientPacked : Number(computedTotalWeight) || 0;

        // Persist authoritative total weight fields onto the savedOrder object
        try {
          savedOrder.totalWeightKg = finalWeight;
          savedOrder.packedweight = finalWeight;
        } catch (setErr) {
          console.warn('Error setting totalWeightKg/packedweight on savedOrder', id, setErr && (setErr.stack || setErr.message));
        }

        // Force-write these fields to the DB immediately to avoid any
        // inconsistencies due to document state / later saves.
        try {
          console.log(`PUT /api/orders/${id} - computedTotalWeight:`, Number(computedTotalWeight) || 0, ' clientPacked:', clientPacked);
          const forced = await Order.findOneAndUpdate(
            { id },
            { $set: { totalWeightKg: finalWeight, packedweight: finalWeight } },
            { new: true }
          );
          console.log(`PUT /api/orders/${id} - force-update result:`, forced ? JSON.stringify({ id: forced.id, totalWeightKg: forced.totalWeightKg, packedweight: forced.packedweight }, null, 2) : '<no doc>');
          if (forced) {
            // Replace savedOrder with DB authoritative document so subsequent
            // modifications operate on the latest state.
            savedOrder = forced;
          } else {
            // If findOneAndUpdate returned null for some reason, re-load the doc
            try { savedOrder = await Order.findOne({ id }); } catch (reErr) { /* swallow */ }
          }
          // Ensure the in-memory savedOrder has the computed weights as numbers
          if (savedOrder) {
            savedOrder.totalWeightKg = Number(savedOrder.totalWeightKg) || finalWeight || 0;
            savedOrder.packedweight = Number(savedOrder.packedweight) || finalWeight || 0;
          }
        } catch (forceErr) {
          console.warn('Error force-updating order totalWeightKg/packedweight for', id, forceErr && (forceErr.stack || forceErr.message));
        }

        const pfDoc = {
          orderId: id,
          merchantId: savedOrder.merchantId,
          items: pfItems,
          trackingFee,
          boxFee,
          boxCutting,
          totalPackingFee,
          totalWeightKg: Number(savedOrder.totalWeightKg || savedOrder.packedweight || 0),
          updatedAt: new Date().toISOString()
        };

        await PackingFee.findOneAndUpdate({ orderId: id }, pfDoc, { upsert: true, new: true });
        console.log(`PUT /api/orders/${id} - PackingFee document computed & upserted for order ${id}`);

        // Also persist server-calculated per-item breakdown onto the order for immediate client consumption
        try {
          savedOrder.packingDetails = pfItems;
        } catch (e) {
          console.warn('Failed to attach packingDetails to savedOrder object', e);
        }

        if (Number(savedOrder.packingFee || 0) !== totalPackingFee) {
          savedOrder.packingFee = totalPackingFee;
        }
        // Save once with both packingFee and packingDetails
        await savedOrder.save();
        console.log(`PUT /api/orders/${id} - order.packingFee and packingDetails updated to server-calculated values (${totalPackingFee})`);
      }
    } catch (pfErr) {
      console.error('Error computing/upserting PackingFee doc for order', id, pfErr);
    }
    // Return an authoritative fresh copy from DB so client receives exactly what's persisted
    try {
      const fresh = await Order.findOne({ id });
      console.log(`PUT /api/orders/${id} - final authoritative DB copy:`, JSON.stringify(fresh ? fresh.toObject() : null, null, 2));
      return res.json(fresh || savedOrder);
    } catch (e) {
      console.warn('PUT /api/orders/:id - failed to fetch fresh order after save', e);
      return res.json(savedOrder);
    }
  } catch (err) {
    console.error('Error updating order:', err);
    res.status(500).json({ error: 'Internal Server Error', details: err.message });
  }
});

// Add DELETE endpoint to remove an order by id
app.delete('/api/orders/:id', authenticateToken, async (req, res) => {
  const id = req.params.id;
  console.log(`DELETE /api/orders/${id} called by user: ${req.user?.id} (${req.user?.role})`);
  try {
    const order = await Order.findOne({ id });
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }
    // Allow if requester is admin/superadmin or the merchant who owns the order
    const requester = req.user || {};
    if (requester.role === 'admin' || requester.role === 'superadmin' || (requester.role === 'merchant' && requester.id === order.merchantId)) {
      await Order.findOneAndDelete({ id });
      // Optionally, also remove related transactions or perform cleanup here
      return res.json({ message: 'Order deleted', id });
    }
    return res.status(403).json({ error: 'Forbidden: insufficient permissions to delete order' });
  } catch (err) {
    console.error('Error deleting order:', err);
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
  dispatchedQuantity: { type: Number, default: 0 },
  packedQuantity: { type: Number, default: 0 },
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

// Shipping Template schema and model
const shippingTemplateSchema = new mongoose.Schema({
  merchantId: { type: String, required: true, unique: true },
  template: { type: String, default: '' },
  updatedAt: { type: Date, default: Date.now }
});
const ShippingTemplate = mongoose.model('ShippingTemplate', shippingTemplateSchema);

// GET shipping template for merchant
app.get('/api/merchants/:id/shipping-template', async (req, res) => {
  const id = req.params.id;
  try {
    const doc = await ShippingTemplate.findOne({ merchantId: id });
    // Return 200 with empty template when not found to avoid noisy 404 in the frontend console.
    if (!doc) return res.json({ template: '', updatedAt: null });
    return res.json({ template: doc.template, updatedAt: doc.updatedAt });
  } catch (err) {
    console.error('Error fetching shipping template:', err);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

// PUT (create/update) shipping template for merchant
app.put('/api/merchants/:id/shipping-template', async (req, res) => {
  const id = req.params.id;
  const { template } = req.body || {};
  try {
    const updated = await ShippingTemplate.findOneAndUpdate(
      { merchantId: id },
      { template: template || '', updatedAt: new Date() },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );
    return res.json({ template: updated.template, updatedAt: updated.updatedAt });
  } catch (err) {
    console.error('Error saving shipping template:', err);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
});

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
    // Sanitize and normalize numeric fields to ensure schema consistency
    const sanitized = {
      ...productData,
      // Normalize `skus` to an array of strings when provided by frontend
      skus: Array.isArray(productData.skus) ? productData.skus.map(s => String(s)) : (productData.skus ? [String(productData.skus)] : []),
      // Ensure we persist a single `sku` (backwards-compatibility) using first element from `skus` when available
      sku: (Array.isArray(productData.skus) && productData.skus.length > 0) ? String(productData.skus[0]) : (productData.sku || ''),
      price: productData.price === undefined || productData.price === null ? 0 : Number(productData.price),
      cost: productData.cost === undefined || productData.cost === null ? 0 : Number(productData.cost),
      weightKg: productData.weightKg === undefined || productData.weightKg === null ? 0 : Number(productData.weightKg),
      transportationFee: productData.transportationFee === undefined || productData.transportationFee === null ? 0 : Number(productData.transportationFee),
      itemPackingFee: productData.itemPackingFee === undefined || productData.itemPackingFee === null ? 0 : Number(productData.itemPackingFee),
      warehousingRatePerKg: productData.warehousingRatePerKg === undefined || productData.warehousingRatePerKg === null ? 0 : Number(productData.warehousingRatePerKg),
    };

    const newProduct = new Product(sanitized);
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
    // Normalize numeric fields before updating
    const updatePayload = {
      ...updatedData,
      ...(updatedData.price !== undefined && { price: Number(updatedData.price) }),
      ...(updatedData.cost !== undefined && { cost: Number(updatedData.cost) }),
      ...(updatedData.weightKg !== undefined && { weightKg: Number(updatedData.weightKg) }),
      ...(updatedData.transportationFee !== undefined && { transportationFee: Number(updatedData.transportationFee) }),
      ...(updatedData.itemPackingFee !== undefined && { itemPackingFee: Number(updatedData.itemPackingFee) }),
      ...(updatedData.warehousingRatePerKg !== undefined && { warehousingRatePerKg: Number(updatedData.warehousingRatePerKg) }),
    };
    // If client provided `skus`, normalize and persist the array and also keep `sku` fallback
    if (updatedData.skus !== undefined) {
      updatePayload.skus = Array.isArray(updatedData.skus) ? updatedData.skus.map(s => String(s)) : [String(updatedData.skus || '')];
      if (Array.isArray(updatePayload.skus) && updatePayload.skus.length > 0) {
        updatePayload.sku = String(updatePayload.skus[0] || '');
      }
    } else if (updatedData.sku !== undefined) {
      updatePayload.sku = String(updatedData.sku || '');
    }

    const updatedProduct = await Product.findOneAndUpdate({ id }, updatePayload, { new: true });
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

// PATCH endpoint to partially update inventory item
app.patch('/api/inventory/:id', async (req, res) => {
  const id = req.params.id;
  const updateFields = req.body;
  try {
    const updatedInventory = await Inventory.findOneAndUpdate(
      { id },
      { $set: updateFields },
      { new: true }
    );
    if (!updatedInventory) return res.status(404).json({ error: 'Inventory item not found' });
    res.json(updatedInventory);
  } catch (err) {
    console.error('Error patching inventory:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Create inventory item with specific id if not exists
// NOTE: route renamed to avoid collision with other literal paths (e.g. 'dispatched-aggregate')
app.post('/api/inventory/create/:id', async (req, res) => {
  const id = req.params.id;
  const data = req.body;
  try {
    const existing = await Inventory.findOne({ id });
    if (existing) {
      return res.status(409).json({ error: 'Inventory item already exists' });
    }
    const newInventory = new Inventory({ ...data, id });
    await newInventory.save();
    res.status(201).json(newInventory);
  } catch (err) {
    console.error('Error creating inventory item:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// POST endpoint to accept aggregated dispatched quantities for multiple merchant/product pairs.
// Body: [{ merchantId, productId, dispatched }] — sets `dispatchedQuantity` on inventory documents.
app.post('/api/inventory/dispatched-aggregate', async (req, res) => {
  try {
    const list = req.body;
    if (!Array.isArray(list)) {
      return res.status(400).json({ error: 'Expected an array of { merchantId, productId, dispatched }' });
    }
    const results = [];
    for (const entry of list) {
      const merchantId = entry.merchantId;
      const productId = entry.productId;
      const dispatched = Number(entry.dispatched || 0);
      if (!merchantId || !productId) continue;

      // Use upsert to create or update a document safely (avoid duplicate-create conflicts)
      const updateDoc = {
        $set: {
          productId,
          merchantId,
          dispatchedQuantity: dispatched,
          location: 'Default Warehouse',
          minStockLevel: 0,
          maxStockLevel: 0,
        }
      };
      const options = { upsert: true, new: true, setDefaultsOnInsert: true };
      const upserted = await Inventory.findOneAndUpdate({ merchantId, productId }, updateDoc, options);
      results.push({ merchantId, productId, id: upserted.id, dispatchedQuantity: upserted.dispatchedQuantity });
    }
    return res.json({ ok: true, results });
  } catch (err) {
    console.error('Error storing dispatched aggregate', err);
    return res.status(500).json({ error: 'Failed to store dispatched aggregate' });
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
  } = req.body || {};
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
  } = req.body || {};
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
  const { email, merchantId, phone } = req.body || {};
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

    // Dev helper: optionally return OTP in response when testing locally
    if (process.env.NODE_ENV !== 'production' && process.env.DEV_RETURN_OTP === 'true') {
      console.log(`DEV_RETURN_OTP enabled. Returning OTP for userId=${user.id}`);
      return res.json({ message: 'OTP sent (dev)', userId: user.id, otp });
    }

    await sendOtpEmail(user.email, otp);
    res.json({ message: 'OTP sent to registered email', userId: user.id });
  } catch (err) {
    console.error('Error in request-otp:', err);
    if (process.env.NODE_ENV !== 'production' || process.env.DEV_DEBUG === 'true') {
      return res.status(500).json({ error: 'Internal Server Error', detail: err.message });
    }
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// POST /api/register/request-otp
app.post('/api/register/request-otp', async (req, res) => {
  const { email } = req.body || {};
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }
  try {
    const otp = generateOTP();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // OTP valid for 10 minutes
    otpStore[email] = { otp, expiresAt };
    // Dev helper: optionally return OTP in response when testing locally
    if (process.env.NODE_ENV !== 'production' && process.env.DEV_RETURN_OTP === 'true') {
      console.log(`DEV_RETURN_OTP enabled. Returning OTP for email=${email}`);
      return res.json({ message: 'OTP sent (dev)', email, otp });
    }

    await sendOtpEmail(email, otp);
    res.json({ message: 'OTP sent to email', email });
  } catch (err) {
    console.error('Error in register request-otp:', err);
    if (process.env.NODE_ENV !== 'production' || process.env.DEV_DEBUG === 'true') {
      return res.status(500).json({ error: 'Internal Server Error', detail: err.message });
    }
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// POST /api/register/verify-otp
app.post('/api/register/verify-otp', (req, res) => {
  const { email, otp } = req.body || {};
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
  const { userId, otp } = req.body || {};
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
  const { userId, newPassword } = req.body || {};
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

// Middleware to verify JWT and attach user to request
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'Authorization header missing' });
  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token missing' });
  jwt.verify(token, process.env.JWT_SECRET || 'defaultsecret', (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = decoded;
    next();
  });
}

// POST /login endpoint
app.post('/login', async (req, res) => {
  const { email, password } = req.body || {};
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
    // Sign a JWT so clients can authenticate subsequent requests
    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET || 'defaultsecret', { expiresIn: '8h' });
    res.json({ message: 'Login successful', user: userInfo, token });
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

// Middleware to authenticate and authorize superadmin
function authenticateSuperadmin(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    return res.status(401).json({ error: 'Authorization header missing' });
  }
  const token = authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Token missing' });
  }
  jwt.verify(token, process.env.JWT_SECRET || 'defaultsecret', (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    if (!decoded || decoded.role !== 'superadmin') {
      return res.status(403).json({ error: 'Forbidden: Superadmin only' });
    }
    req.user = decoded;
    next();
  });
}

// DELETE endpoint to delete a user by id (superadmin only)
app.delete('/api/users/:id', authenticateSuperadmin, async (req, res) => {
  const id = req.params.id;
  try {
    const deletedUser = await User.findOneAndDelete({ id });
    if (!deletedUser) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ message: 'User deleted' });
  } catch (err) {
    console.error('Error deleting user:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Decrement inventory quantity endpoint
app.post('/api/inventory/:id/decrement', async (req, res) => {
  const id = req.params.id;
  const { quantity } = req.body || {};
  if (typeof quantity !== 'number' || quantity <= 0) {
    return res.status(400).json({ error: 'Quantity to decrement must be a positive number' });
  }
  try {
    const inventoryItem = await Inventory.findOne({ id });
    if (!inventoryItem) {
      return res.status(404).json({ error: 'Inventory item not found' });
    }
    if (typeof inventoryItem.quantity !== 'number' || inventoryItem.quantity < quantity) {
      return res.status(400).json({ error: 'Not enough stock to decrement' });
    }
    inventoryItem.quantity -= quantity;
    await inventoryItem.save();
    res.json(inventoryItem);
  } catch (err) {
    console.error('Error decrementing inventory:', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// POST endpoint to accept aggregated dispatched quantities for multiple merchant/product pairs.
// Body: [{ merchantId, productId, dispatched }] — sets `dispatchedQuantity` on inventory documents.
app.post('/api/inventory/dispatched-aggregate', async (req, res) => {
  try {
    const list = req.body;
    if (!Array.isArray(list)) {
      return res.status(400).json({ error: 'Expected an array of { merchantId, productId, dispatched }' });
    }
    const results = [];
    for (const entry of list) {
      const merchantId = entry.merchantId;
      const productId = entry.productId;
      const dispatched = Number(entry.dispatched || 0);
      if (!merchantId || !productId) continue;

      let inv = await Inventory.findOne({ merchantId: merchantId, productId: productId });
      if (inv) {
        inv.dispatchedQuantity = dispatched;
        await inv.save();
        results.push({ merchantId, productId, id: inv.id, dispatchedQuantity: inv.dispatchedQuantity });
      } else {
        // Use upsert to create or update a document safely (avoid duplicate-create conflicts)
        const updateDoc = {
          $set: {
            productId,
            merchantId,
            dispatchedQuantity: dispatched,
            location: 'Default Warehouse',
            minStockLevel: 0,
            maxStockLevel: 0,
          }
        };
        const options = { upsert: true, new: true, setDefaultsOnInsert: true };
        const upserted = await Inventory.findOneAndUpdate({ merchantId, productId }, updateDoc, options);
        results.push({ merchantId, productId, id: upserted.id, dispatchedQuantity: upserted.dispatchedQuantity });
      }
    }
    return res.json({ ok: true, results });
  } catch (err) {
    console.error('Error storing dispatched aggregate', err);
    return res.status(500).json({ error: 'Failed to store dispatched aggregate' });
  }
});

// PATCH endpoint to update tracking code for an order
app.patch('/api/orders/:id/tracking-code', async (req, res) => {
  console.log(`PATCH request received for /api/orders/${req.params.id}/tracking-code`);
  const id = req.params.id;
  // Accept trackingCode even if empty string; ensure property exists in body
  const hasTrackingCodeProp = Object.prototype.hasOwnProperty.call(req.body, 'trackingCode');
  if (!hasTrackingCodeProp) {
    console.log('Tracking code property is missing in the request body');
    return res.status(400).json({ error: 'trackingCode property is required in body' });
  }
  const { trackingCode } = req.body;

  try {
    const order = await Order.findOne({ id });
    if (!order) {
      console.log(`Order with id ${id} not found`);
      return res.status(404).json({ error: 'Order not found' });
    }

    // Update the tracking code and re-query to ensure latest doc is returned
    order.trackingCode = trackingCode;
    await order.save();
    const saved = await Order.findOne({ id });
    console.log(`Tracking code updated successfully for order ${id}`, { trackingCode: saved && saved.trackingCode });
    res.json({ message: 'Tracking code updated successfully', order: saved });
  } catch (err) {
    console.error('Error updating tracking code:', err);
    res.status(500).json({ error: 'Internal Server Error', details: err.message });
  }
});

// NOTE: POST /api/orders/:id/tracking-code removed — use PATCH /api/orders/:id/tracking-code or PUT /api/orders/:id

// GET packing fee for a specific order by orderId
app.get('/api/packingfees/:orderId', async (req, res) => {
  const orderId = req.params.orderId;
  try {
    const pf = await PackingFee.findOne({ orderId });
    if (!pf) return res.status(404).json({ error: 'PackingFee not found for orderId', orderId });
    // Return minimal payload to the client
    return res.json({
      orderId: pf.orderId,
      merchantId: pf.merchantId,
      totalPackingFee: pf.totalPackingFee,
      totalWeightKg: pf.totalWeightKg,
      boxFee: pf.boxFee,
      boxCutting: pf.boxCutting,
      trackingFee: pf.trackingFee,
      updatedAt: pf.updatedAt
    });
  } catch (err) {
    console.error('Error fetching PackingFee for', orderId, err);
    return res.status(500).json({ error: 'Internal Server Error', details: err.message });
  }
});

// Batch GET packing fees for multiple orderIds
// Accepts either `?orderIds=ord-1,ord-2` or repeated `?orderId=ord-1&orderId=ord-2`
app.get('/api/packingfees', async (req, res) => {
  try {
    let ids = [];
    if (req.query.orderIds) {
      ids = String(req.query.orderIds).split(',').map(s => s.trim()).filter(Boolean);
    } else if (req.query.orderId) {
      if (Array.isArray(req.query.orderId)) ids = req.query.orderId; else ids = [req.query.orderId];
    }
    if (!ids || ids.length === 0) return res.status(400).json({ error: 'orderIds query parameter is required' });
    const docs = await PackingFee.find({ orderId: { $in: ids } });
    // return mapping by orderId
    const map = {};
    docs.forEach(d => {
      map[d.orderId] = {
        orderId: d.orderId,
        merchantId: d.merchantId,
        totalPackingFee: d.totalPackingFee,
        totalWeightKg: d.totalWeightKg,
        boxFee: d.boxFee,
        boxCutting: d.boxCutting,
        trackingFee: d.trackingFee,
        updatedAt: d.updatedAt
      };
    });
    return res.json({ map });
  } catch (err) {
    console.error('Error fetching packingfees batch', err);
    return res.status(500).json({ error: 'Internal Server Error', details: err.message });
  }
});


// Start server (PUBLIC)
// Shopify HMAC verifier
function verifyShopifyHmac(rawBody, hmacHeader, secret) {
  try {
    const generated = crypto.createHmac('sha256', secret).update(rawBody).digest();
    const headerBuf = Buffer.from(String(hmacHeader || ''), 'base64');
    if (!headerBuf || headerBuf.length !== generated.length) return false;
    return crypto.timingSafeEqual(generated, headerBuf);
  } catch (e) {
    return false;
  }
}

// Shopify webhook route
app.post(
  "/internal/shopify/webhook",
  async (req, res) => {
    try {
      const shopDomain = req.headers["x-shopify-shop-domain"];
      const hmacHeader = req.headers["x-shopify-hmac-sha256"];
      const webhookId = req.headers["x-shopify-webhook-id"];

      if (!shopDomain || !hmacHeader || !webhookId) {
        return res.status(400).send("Missing Shopify headers");
      }

      // 🔁 Duplicate webhook protection
      const existing = await Order.findOne({
        shopifyWebhookId: webhookId
      });

      if (existing) {
        return res.status(200).send("Duplicate webhook ignored");
      }

      // 🔍 Find active webhook config
      const webhook = await Webhook.findOne({
        shopifyDomain: shopDomain,
        topic: "orders/create",
        active: true
      });

      if (!webhook) {
        return res.status(401).send("Webhook not registered");
      }

      // 🔐 Verify signature using captured raw body
      const raw = req.rawBody || (req.body && Buffer.from(JSON.stringify(req.body))) || Buffer.alloc(0);
      const isValid = verifyShopifyHmac(raw, hmacHeader, webhook.signature);

      if (!isValid) {
        return res.status(401).send("Invalid Shopify signature");
      }

      const payload = JSON.parse((req.rawBody || Buffer.from(JSON.stringify(req.body))).toString());

      await createShopifyOrder(
        payload,
        webhook.merchantId,
        webhookId
      );

      res.status(200).send("OK");
    } catch (err) {
      console.error("Shopify webhook error:", err);
      res.status(500).send("Server error");
    }
  }
);

// Create order from Shopify payload
async function createShopifyOrder(payload, merchantId, webhookId) {
  if (payload.financial_status !== "paid") return;

  const orderItems = [];

  for (const item of payload.line_items) {
    if (!item.sku) continue;

    const sku = item.sku.trim().toLowerCase();

    const product = await Product.findOne({
      merchantId: merchantId,
      $or: [
        { sku: { $regex: `^${sku}$`, $options: "i" } },
        { skus: { $elemMatch: { $regex: `^${sku}$`, $options: "i" } } }
      ]
    });

    if (!product) continue;

    const warehousingFee =
      product.warehousingRatePerKg *
      product.weightKg *
      item.quantity;

    const packingFee =
      product.itemPackingFee *
      item.quantity;

    const transportationFee =
      product.transportationFee *
      item.quantity;

    const estimatedTotal =
      warehousingFee +
      packingFee +
      transportationFee;

    orderItems.push({
      productId: product.id,
      name: product.name,
      sku: item.sku,
      quantity: item.quantity,

      weightKg: product.weightKg,

      warehousingPerItem: warehousingFee,
      transportationPerItem: transportationFee,
      itemPackingPerItem: packingFee,
      estimatedTotalPerItem: estimatedTotal,
      lineTotal: estimatedTotal
    });
  }

  if (!orderItems.length) return;

  const order = new Order({
    id: `ord-${Date.now()}`,
    merchantId: merchantId,

    customerName: payload.shipping_address?.name,
    address: payload.shipping_address?.address1,
    city: payload.shipping_address?.city,
    state: payload.shipping_address?.province,
    pincode: payload.shipping_address?.zip,
    phone: payload.shipping_address?.phone,

    items: orderItems,
    source: "shopify",
    status: "pending",

    shopifyWebhookId: webhookId,

    packedweight: orderItems.reduce(
      (sum, i) => sum + i.weightKg * i.quantity,
      0
    ),

    date: new Date().toISOString().slice(0, 10),
    time: new Date().toLocaleTimeString()
  });

  await order.save();
}

// Start server (PUBLIC)
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});

