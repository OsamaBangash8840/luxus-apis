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
    owner:{type:mongoose.Schema.Types.ObjectId,ref:"User"},
    title: String,
    description: String,
    price: Number,
    location: String,
    type: String,
    buildYear: Number,
    size: String,
    lotSize: String,
    amenities: [String],
    images: [String],
    mapLocation: {
        lat: Number,
        lng: Number
    },
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
    }
});

const Category = mongoose.model('Category', categorySchema);
const Property = mongoose.model('Property', propertySchema);

module.exports = { Property, Category };
