const express = require('express');
const router = express.Router();
const Review = require('../models/Reviews'); // Adjust the path as necessary
const mongoose = require('mongoose');

// Endpoint to submit a review
router.post('/properties/:id/reviews', async (req, res) => {
    const { id } = req.params;
    const { name, email, message, rating } = req.body;

    try {
        // Validate the property ID if needed
        const isValidObjectId = mongoose.Types.ObjectId.isValid(id);
        if (!isValidObjectId) {
            return res.status(400).send("Invalid Property Id");
        }

        const newReview = new Review({
            name,
            email,
            message,
            rating,
        });

        await newReview.save();
        res.status(201).json(newReview);
    } catch (error) {
        console.log(error);
        res.status(500).send("Internal Server Error");
    }
});

module.exports = router;
