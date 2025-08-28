const User = require('../models/user.model');

const { signAccessToken, signRefreshToken, verifyRefreshToken } = require('../utils/jwt');

const cookieOpts = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    path: '/'
};

const setAccessCookie = (res, token) => {
    res.cookie('accessToken', token, { ...cookieOpts, maxAge: 15 * 60 * 1000 });
};

const setRefreshCookie = (res, token) => {
    res.cookie('refreshToken', token, { ...cookieOpts, maxAge: 7 * 24 * 60 * 60 * 1000 });
};

exports.register = async (req, res) => {
    try {
        const { name, email, password, role } = req.body;

        // Check if user exists
        const exists = await User.findOne({ email }).lean();
        if (exists) {
            return res.status(409).json({ message: 'Email already registered' });
        }

        // Create new user
        const user = new User({ name, email, password, role });

        // Generate tokens
        const accessToken = signAccessToken(user._id.toString(), user.role);
        const refreshToken = signRefreshToken(user._id.toString(), user.role);

        // Save refresh token
        user.refreshToken = refreshToken; // make sure schema has this field
        await user.save();

        // Set cookies
        setAccessCookie(res, accessToken);
        setRefreshCookie(res, refreshToken);

        return res.status(201).json({
            user: { id: user._id, name: user.name, email: user.email, role: user.role },
            accessToken
        });

    } catch (err) {
        console.error(err);
        return res.status(400).json({ message: err.message || "Validation failed" });
    }
};


exports.login = async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email }).select('+password +refreshTokenHash');

    if (!user) return res.status(401).json({ message: 'Invalid credentials' });
        const ok = await user.comparePassword(password);
        if (!ok) return res.status(401).json({ message: 'Invalid credentials' });
        const accessToken = signAccessToken(user._id.toString(), user.role);
        const refreshToken = signRefreshToken(user._id.toString(), user.role);
        await user.setRefreshToken(refreshToken);
        await user.save();
        setAccessCookie(res, accessToken);
        setRefreshCookie(res, refreshToken);
        res.json({ user: user.toJSON(), accessToken });
};

exports.refresh = async (req, res) => {
    const token = req.cookies?.refreshToken;
    if (!token) return res.status(401).json({ message: 'Missing refresh token' });
    let payload;
    try {
        payload = verifyRefreshToken(token);
    } catch {
        return res.status(401).json({ message: 'Invalid refresh token' });
    }
    const user = await User.findById(payload.sub).select('+refreshTokenHash');
        if (!user) return res.status(401).json({ message: 'User not found' });
            const match = await user.matchesRefreshToken(token);
            if (!match) return res.status(401).json({ message: 'Refresh tokenmismatch' });
            const newAccess = signAccessToken(user._id.toString(), user.role);
            const newRefresh = signRefreshToken(user._id.toString(), user.role);
            await user.setRefreshToken(newRefresh);
            await user.save();
            setAccessCookie(res, newAccess);
            setRefreshCookie(res, newRefresh);
            res.json({ accessToken: newAccess });
};

exports.logout = async (req, res) => {
    const token = req.cookies?.refreshToken;
    if (token) {
    try {
        const payload = verifyRefreshToken(token);
        const user = await User.findById(payload.sub).select('+ refreshTokenHash');
        if (user) {
            user.refreshTokenHash = undefined;
            await user.save();
        }
        } catch {}
    }
        res.clearCookie('accessToken', { path: '/' });
        res.clearCookie('refreshToken', { path: '/' });
        res.json({ message: 'Logged out' });
};

exports.me = async (req, res) => {
    const user = await User.findById(req.user.id).lean();
    res.json({ user });
};

















