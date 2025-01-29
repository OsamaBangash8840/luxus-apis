const mongoose = require("mongoose");

const regSchema = new mongoose.Schema({
    username: {
        type: String,
        min: 3,
        max: 100,
        required: true,
    },
    email: {
        type: String,
        min: 3,
        max: 100,
        unique: true,
        required: true,
    },
    password: {
        type: String,
        min: 8,
        max: 30,
    },
    role: {
        type: String,
        enum: ['buyer', 'seller', 'admin'],
        default: 'buyer'
    }
    ,
    googleId: {
        type: String,
        unique: true,
        sparse: true, // Allows for unique but optional fields
    },
    avatar: {
        type: String,
    },
    resetPasswordToken: String,
    resetPasswordExpires: Date,
    date: {
        type: Date,
        default: Date.now,
    },
    properties: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Property'
    },
    authMethod: {
        type: String,
        enum: ['local', 'google'],
        default: 'local'
    },
    isVerified: {
        type: Boolean,
        default: false
    },
    verificationToken: {
        type: String
    },
    verificationTokenExpires: {
        type: Date
    }
});

module.exports = mongoose.model("User", regSchema);
