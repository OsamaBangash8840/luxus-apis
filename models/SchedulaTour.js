const mongoose = require('mongoose');

const TourSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
    },
    phone: {
        type: Number,
        required: true,
    },
    date: {
        type: Date,
        default: Date.now,
    },
    message: {
        type: String,
        required: true,
    }
});

module.exports = mongoose.model("SchedulaTour", TourSchema);
