const mongoose = require('mongoose');

const categorySchema = new mongoose.Schema({
    name: {
        type: String,
        ref: 'Category',
        enum: ['apartment', 'condo', 'house', 'villa', 'shop', 'office'],
        required: true
    },
    images: [String] // Array of image URLs for the category
});

const propertySchema = new mongoose.Schema({
    owner: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    title: String,
    description: String,
    price: Number,
    location: {
        type: { type: String, enum: ['Point'], required: true },
        coordinates: { type: [Number], required: true }, // [longitude, latitude]
    },
    type: String,
    buildYear: Number,
    size: String,
    lotSize: String,
    amenities: [String],
    images: [String],
    reviews: [{
        name: String,
        date: Date,
        rating: Number,
        comment: String
    }],
    category: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Category',
        required: true
    },
    seller: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    status: {
        type: String,
        enum: ['active', 'pending', 'sold'],
        default: 'pending'
    }
});

// Create a 2dsphere index on the `location` field
propertySchema.index({ location: "2dsphere" });

const Category = mongoose.model('Category', categorySchema);
const Property = mongoose.model('Property', propertySchema);

module.exports = { Property, Category };
