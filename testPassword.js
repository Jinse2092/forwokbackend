const bcrypt = require('bcrypt');

const password = '123456';
const hash = '$2b$10$yQA2M1Ry8r8opVi6GHz1BuVBF5qvi3HHxn8pGLbGIc5cNr4YmW242';

bcrypt.compare(password, hash, (err, result) => {
  if (err) {
    console.error('Error comparing password:', err);
    return;
  }
  console.log('Password match:', result);
});
