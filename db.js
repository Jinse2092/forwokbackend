const { MongoClient, ObjectId } = require('mongodb');

const mongoUri = 'mongodb+srv://<db_username>:<db_password>@cluster0.z5ryn8i.mongodb.net/?retryWrites=true&w=majority'; // Replace with your MongoDB URI
const client = new MongoClient(mongoUri);

let db;

async function connect() {
  if (db) return db;
  await client.connect();
  db = client.db('forvoqdb'); // Database name
  console.log('Connected to MongoDB');
  return db;
}

function getObjectId(id) {
  return new ObjectId(id);
}

module.exports = {
  connect,
  getObjectId,
};
