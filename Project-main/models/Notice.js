// models/Notice.js
const mongoose = require('mongoose');

const noticeSchema = new mongoose.Schema({
    title: { type: String, required: true },
    content: { type: String, required: true },
    createdBy: { type: String, required: true }, // To track who created the notice
    createdAt: { type: Date, default: Date.now },
});

const Notice = mongoose.model('Notice', noticeSchema);
module.exports = Notice;