// models/User.js
const mongoose = require('mongoose');


    const userSchema = new mongoose.Schema({
        username: { 
            type: String, 
            required: true, 
            unique: true 
        },
        email: {
            type: String,
            required: true,
            unique: true,
            validate: {
                validator: function(v) {
                    return /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/.test(v);
                },
                message: props => `${props.value} is not a valid email address!`
            }
        },
        password: { 
            type: String, 
            required: true 
        },
        branch: { 
            type: String, 
            enum: ['cs', 'it', 'aids', 'extc'], 
            required: true,
            lowercase: true 
        },
        year: { 
            type: Number, 
            enum: [1, 2, 3, 4], 
            required: true 
        },
        phone: { 
            type: String, 
            required: true, 
            validate: {
                validator: function(v) {
                    return /^\d{10}$/.test(v);
                },
                message: props => `${props.value} is not a valid 10-digit phone number!`
            }
        },
        role: { 
            type: String, 
            enum: ['student', 'faculty', 'admin'], 
            required: true,
            lowercase: true 
        },
        resetPasswordToken: String,
        resetPasswordExpires: Date
    }, { timestamps: true });
module.exports = mongoose.model('User', userSchema);