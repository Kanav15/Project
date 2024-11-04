// models/File.js
const mongoose = require('mongoose');

const fileSchema = new mongoose.Schema({
    filename: { type: String, required: true },
    originalname: { type: String, required: true },
    subject: { type: String, required: true },
    uploadedBy: { type: String, required: true },
    uploadDate: { type: Date, default: Date.now },
    path: { type: String, required: true },
    fileType: { type: String, required: true }
});

module.exports = mongoose.model('File', fileSchema);