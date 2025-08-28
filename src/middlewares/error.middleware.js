const { ZodError } = require('zod');

const notFound = (req, res) => {
    res.status(404).json({ message: 'Route not found' });
};

const errorHandler = (err, req, res, next) => {
    if (err instanceof ZodError) {
        return res.status(400).json({
            message: 'Validation failed',
            errors: err.errors
        });
    }
    const status = err.status || 500;
    const message = err.message || 'Internal Server Error';
    if (process.env.NODE_ENV !== 'production') console.error(err);
    res.status(status).json({ message });
};
module.exports = { notFound, errorHandler };