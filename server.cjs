const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 4000;

app.use(cors());
app.use(bodyParser.json());

console.log('Starting server setup...');

// Add receivedPayments file path
const receivedPaymentsFile = path.join(__dirname, 'receivedPayments.json');

// Helper to read received payments
const readReceivedPayments = () => {
  try {
    if (!fs.existsSync(receivedPaymentsFile)) {
      fs.writeFileSync(receivedPaymentsFile, JSON.stringify([]));
    }
    const data = fs.readFileSync(receivedPaymentsFile, 'utf-8');
    return JSON.parse(data);
  } catch (err) {
    console.error('Error reading receivedPayments.json:', err);
    return [];
  }
};

// Helper to write received payments
const writeReceivedPayments = (payments) => {
  try {
    fs.writeFileSync(receivedPaymentsFile, JSON.stringify(payments, null, 2));
  } catch (err) {
    console.error('Error writing receivedPayments.json:', err);
  }
};

// GET endpoint for received payments
app.get('/api/received-payments', (req, res) => {
  const payments = readReceivedPayments();
  res.json(payments);
});

// POST endpoint to add a received payment
app.post('/api/received-payments', (req, res) => {
  const newPayment = req.body;
  if (!newPayment || !newPayment.merchantId || !newPayment.amount) {
    return res.status(400).json({ error: 'Invalid payment data' });
  }
  const payments = readReceivedPayments();
  newPayment.id = Date.now().toString();
  newPayment.date = newPayment.date || new Date().toISOString().split('T')[0];
  payments.unshift(newPayment);
  writeReceivedPayments(payments);
  res.status(201).json(newPayment);
});

console.log('Starting server setup...');

const dataFiles = {
  products: path.join(__dirname, 'products.json'),
  inventory: path.join(__dirname, 'inventory.json'),
  transactions: path.join(__dirname, 'transactions.json'),
  orders: path.join(__dirname, 'orders.json'),
  inbounds: path.join(__dirname, 'inbounds.json'),
  users: path.join(__dirname, 'users.json'),
  currentUser: path.join(__dirname, 'currentUser.json'),
  savedPickupLocations: path.join(__dirname, 'savedPickupLocations.json'),
};

// Initialize users.json with superadmin user if file does not exist or is empty
const initializeUsers = () => {
  try {
    console.log('Initializing users.json...');
    if (!fs.existsSync(dataFiles.users)) {
      fs.writeFileSync(dataFiles.users, JSON.stringify([
        { id: 'superadmin-0', email: 'leo112944@gmail.com', password: 'pypyabcd', role: 'superadmin', companyName: 'Super Admin' }
      ], null, 2));
      console.log('Created new users.json with superadmin.');
    } else {
      const usersData = JSON.parse(fs.readFileSync(dataFiles.users));
      const hasSuperAdmin = usersData.some(u => u.email === 'leo112944@gmail.com' && u.role === 'superadmin');
      if (!hasSuperAdmin) {
        usersData.push({ id: 'superadmin-0', email: 'leo112944@gmail.com', password: 'pypyabcd', role: 'superadmin', companyName: 'Super Admin' });
        fs.writeFileSync(dataFiles.users, JSON.stringify(usersData, null, 2));
        console.log('Added superadmin to existing users.json.');
      }
    }
  } catch (err) {
    console.error('Error initializing users.json:', err);
  }
};

initializeUsers();

console.log('Users initialization complete.');

// Helper to read JSON data from file
const readData = (filePath) => {
  try {
    console.log(`Reading data from file: ${filePath}`);
    if (!fs.existsSync(filePath)) {
      console.log(`File does not exist. Creating new file: ${filePath}`);
      fs.writeFileSync(filePath, JSON.stringify([]));
    }
    const data = fs.readFileSync(filePath);
    console.log(`Data successfully read from ${filePath}`);
    return JSON.parse(data);
  } catch (err) {
    console.error(`Error reading file ${filePath}:`, err);
    return [];
  }
};

// Helper to write JSON data to file
const writeData = (filePath, data) => {
  try {
    console.log(`Writing data to file: ${filePath}`);
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    console.log(`Data successfully written to ${filePath}`);
  } catch (err) {
    console.error(`Error writing file ${filePath}:`, err);
  }
};

// Generic GET endpoint for all data types
app.get('/:type', (req, res) => {
  const type = req.params.type;
  if (!dataFiles[type]) {
    return res.status(404).json({ error: 'Invalid data type' });
  }
  const data = readData(dataFiles[type]);
  res.json(data);
});

// Enhanced logging for debugging data persistence
app.post('/:type', (req, res) => {
  const type = req.params.type;
  console.log(`POST request received for type: ${type}`, req.body);
  if (!dataFiles[type]) {
    console.error(`Invalid data type: ${type}`);
    return res.status(404).json({ error: 'Invalid data type' });
  }
  const newItem = req.body;
  if (!newItem || !newItem.id) {
    console.error('POST request missing id field or invalid data:', newItem);
    return res.status(400).json({ error: 'Invalid data' });
  }
  const data = readData(dataFiles[type]);
  console.log(`Current data for ${type}:`, data);
  data.unshift(newItem);
  writeData(dataFiles[type], data);
  console.log(`Updated data for ${type}:`, data);
  res.status(201).json(newItem);
});

app.put('/:type/:id', (req, res) => {
  const type = req.params.type;
  const id = req.params.id;
  console.log(`PUT request received for type: ${type}, id: ${id}`, req.body);
  if (!dataFiles[type]) {
    console.error(`Invalid data type: ${type}`);
    return res.status(404).json({ error: 'Invalid data type' });
  }
  const updatedItem = req.body;
  if (!updatedItem || !updatedItem.id || updatedItem.id !== id) {
    console.error('PUT request invalid data or id mismatch:', updatedItem);
    return res.status(400).json({ error: 'Invalid data or id mismatch' });
  }
  const data = readData(dataFiles[type]);
  console.log(`Current data for ${type}:`, data);
  const index = data.findIndex(item => item.id === id);
  if (index === -1) {
    console.error(`Item with id ${id} not found in ${type}`);
    return res.status(404).json({ error: 'Item not found' });
  }
  // Merge existing item with updated fields to preserve missing fields
  const mergedItem = { ...data[index], ...updatedItem };
  data[index] = mergedItem;
  writeData(dataFiles[type], data);
  console.log(`Updated data for ${type}:`, data);
  res.json(mergedItem);
});

app.delete('/:type/:id', (req, res) => {
  const type = req.params.type;
  const id = req.params.id;
  console.log(`DELETE request received for type: ${type}, id: ${id}`);
  if (!dataFiles[type]) {
    console.error(`Invalid data type: ${type}`);
    return res.status(404).json({ error: 'Invalid data type' });
  }
  const data = readData(dataFiles[type]);
  console.log(`Current data for ${type}:`, data);
  const index = data.findIndex(item => item.id === id);
  if (index === -1) {
    console.error(`Item with id ${id} not found in ${type}`);
    return res.status(404).json({ error: 'Item not found' });
  }
  const deletedItem = data.splice(index, 1)[0];
  writeData(dataFiles[type], data);
  console.log(`Updated data for ${type} after deletion:`, data);
  res.json(deletedItem);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

app.use((err, req, res, next) => {
  console.error('Express error handler:', err);
  res.status(500).json({ error: 'Internal Server Error' });
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

app.post('/api/forgot-password', (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }
  const users = readData(dataFiles.users);
  const user = users.find(u => u.email === email);
  if (!user) {
    return res.status(404).json({ error: 'Email not found' });
  }
  // Simulate sending reset email
  console.log(`Password reset requested for email: ${email}`);
  res.json({ message: 'Password reset instructions sent to your email (simulated).' });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

// Keep the Node.js process alive to prevent immediate exit
setInterval(() => {
  console.log('Server is alive and running...');
}, 60000);

process.on('exit', (code) => {
  console.log(`Process exiting with code: ${code}`);
});

process.on('SIGINT', () => {
  console.log('Received SIGINT. Exiting process.');
  process.exit();
});

process.on('SIGTERM', () => {
  console.log('Received SIGTERM. Exiting process.');
  process.exit();
});
