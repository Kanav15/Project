const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    username: { type: String, required: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['student', 'faculty'], default: 'student' }
});

module.exports = mongoose.model('User', userSchema);