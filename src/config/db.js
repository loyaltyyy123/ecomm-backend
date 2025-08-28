const mongoose = require('mongoose');

module.exports = async () => {
  const uri = process.env.MONGODB_URI;
  if (!uri) throw new Error('MONGODB_URI missing');
  mongoose.set('strictQuery', true);
  await mongoose.connect(uri, {
    autoIndex: process.env.NODE_ENV !== 'production'
  });
  mongoose.connection.on('connected', () => console.log('🗄️  Mongo connected'));
  mongoose.connection.on('error', (err) => console.error('Mongo error', err));
};