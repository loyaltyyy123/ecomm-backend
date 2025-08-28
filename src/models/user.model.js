const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const userSchema = new mongoose.Schema(
{
    name: { type: String, required: true, trim: true, minlength: 2, maxlength:60 },
    email: { type: String, required: true, unique: true, lowercase: true, trim:true, index: true },
    password: { type: String, required: true, minlength: 8, select: false },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    refreshTokenHash: { type: String, select: false }
},{ timestamps: true });

userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
});

userSchema.methods.comparePassword = function (candidate) {
    return bcrypt.compare(candidate, this.password);
};

userSchema.methods.setRefreshToken = async function (token) {
    const salt = await bcrypt.genSalt(10);
    this.refreshTokenHash = await bcrypt.hash(token, salt);
};

userSchema.methods.matchesRefreshToken = function (token) {
    if (!this.refreshTokenHash) return false;
    return bcrypt.compare(token, this.refreshTokenHash);
};

userSchema.methods.toJSON = function () {
    const obj = this.toObject();
    delete obj.password;
    delete obj.refreshTokenHash;
    delete obj.__v;
    return obj;
};

module.exports = mongoose.model('User', userSchema);