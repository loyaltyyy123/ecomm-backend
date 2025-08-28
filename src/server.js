require('dotenv').config();
const app = require('./app');
const connectDB = require('./config/db');
const PORT = process.env.PORT || 8000;
connectDB()
.then(() => {
app.listen(PORT, () => {
    console.log(` ✅ Server listening on ${PORT}`);
});
})
.catch((err) => {
    console.error(' ❌ Failed to connect DB', err); 
    process.exit(1);
});