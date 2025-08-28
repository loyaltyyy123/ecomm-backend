const { verifyAccessToken } = require('../utils/jwt');
const requireAuth = (req, res, next) => {
    try {
        const header = req.headers.authorization || '';
        const token = header.startsWith('Bearer ') ? header.split(' ')[1] :
        req.cookies?.accessToken;
        if (!token) return res.status(401).json({ message: 'Unauthorized' });
        const payload = verifyAccessToken(token);
        req.user = { id: payload.sub, role: payload.role };
        next();
    } catch {
        return res.status(401).json({ message: 'Unauthorized' });
    }
};

const requireRole = (...roles) => (req, res, next) => {
    if (!req.user) return res.status(401).json({ message: 'Unauthorized' });
    if (!roles.includes(req.user.role)) return res.status(403).json({ message:'Forbidden' });
    next();
};

module.exports = { requireAuth, requireRole };