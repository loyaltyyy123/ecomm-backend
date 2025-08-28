const express = require('express');
cors = require('cors');
helmet = require('helmet');
morgan = require('morgan');
cookieParser = require('cookie-parser');
rateLimit = require('express-rate-limit');
const { errorHandler, notFound } = require('./middlewares/error.middleware');
const authRoutes = require('./routes/auth.routes');
const protectedRoutes = require('./routes/protected.routes');
const app = express();
app.set('trust proxy', 1);
app.use(helmet());
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
const allowedOrigin = process.env.CORS_ORIGIN || 'http://localhost:5173';
app.use(cors({ origin: allowedOrigin, credentials: true }));
if (process.env.NODE_ENV !== 'production') app.use(morgan('dev'));
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,  
    legacyHeaders: false
});
app.use('/api/auth', authLimiter);
app.get('/health', (req, res) => res.json({ status: 'ok' }));
app.use('/api/auth', authRoutes);
app.use('/api', protectedRoutes);
app.use(notFound);
app.use(errorHandler);
module.exports = app;