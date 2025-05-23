const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  id: String,
  email: String,
  password: String,
  role: String,
  companyName: String,
});

module.exports = mongoose.model('User', userSchema);
