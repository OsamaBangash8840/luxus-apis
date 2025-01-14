const mongoose = require("mongoose");

const regSchema = new mongoose.Schema({
    name: {
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
});

module.exports = mongoose.model("User", regSchema);
