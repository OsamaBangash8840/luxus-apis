const express = require('express');
const router = express.Router();
const { Property, Category } = require('../models/Property'); // Ensure correct import
const mongoose = require('mongoose');
const verifyToken = require('./verifyToken');


router.post('/properties', verifyToken, async (req, res) => {
    const { title, description, price, location, type, buildYear, size, lotSize, amenities, images, mapLocation, reviews, category } = req.body;

    console.log("Category from payload:", category); // Debug payload category

    try {
        const categoryObj = await Category.findOne({ name: new RegExp(`^${category}$`, 'i') }); // Case-insensitive match
        console.log("Category Object:", categoryObj); // Debug query result

        if (!categoryObj) {
            return res.status(400).json({ error: 'Category not found' });
        }

        const property = new Property({
            title,
            description,
            price,
            location,
            type,
            buildYear,
            size,
            lotSize,
            amenities,
            images,
            mapLocation,
            reviews,
            category: categoryObj._id,
        });

        const newProperty = await property.save();
        res.status(201).json(newProperty);
    } catch (error) {
        console.error("Error:", error);
        res.status(500).json({ error: 'Server error' });
    }
});


router.get('/properties', async (req, res) => {
    try {
        const allProperties = await Property.find({});
        res.status(200).send(allProperties);
    } catch (error) {
        console.error('Error fetching properties:', error);
        res.status(400).send({ error: error.message || 'An error occurred' });
    }
});


router.get('/properties/:id', async (req, res) => {
    const propertyId = req.params.id;

    try {
        const isValidObjectId = mongoose.Types.ObjectId.isValid(propertyId);
        if (!isValidObjectId) {
            return res.status(400).send("Invalid Property Id");
        }
        const property = await Property.findById(propertyId);
        if (!property) {
            return res.status(404).json("Property Not Found");
        }
        res.status(200).json(property);
    } catch (error) {
        console.log(error);
        res.status(500).send("Internal Server Error");
    }
});

router.get('/properties/:id/related', async (req, res) => {
    try {
        const property = await Property.findById(req.params.id).populate('category');
        const relatedProperties = await Property.find({
            category: property.category._id,
            _id: { $ne: property._id }
        }).limit(3); // Fetch 3 related properties excluding the current one
        res.json(relatedProperties);
    } catch (error) {
        res.status(500).json({ error: 'Error fetching related properties' });
    }
});


router.put('/properties/:id', verifyToken, async (req, res) => {
    const propertyId = req.params.id;
    try {
        const isValidObjectId = mongoose.Types.ObjectId.isValid(propertyId);
        if (!isValidObjectId) {
            return res.status(400).send("Invalid Property Id");
        }
        const updatedProperty = await Property.findByIdAndUpdate(propertyId, req.body, { new: true });
        if (!updatedProperty) {
            return res.status(404).send("Property Not Found");
        }
        res.status(200).send(updatedProperty);
    } catch (error) {
        console.log(error);
        res.status(500).send("Internal Server Error");
    }
});

router.delete('/properties/:id', verifyToken, async (req, res) => {
    const propertyId = req.params.id;

    try {
        const isValidObjectId = mongoose.Types.ObjectId.isValid(propertyId);
        if (!isValidObjectId) {
            return res.status(400).send("Invalid Property Id");
        }
        const deletedProperty = await Property.findByIdAndDelete(propertyId);
        if (!deletedProperty) {
            return res.status(404).json("Property Not Found");
        }
        res.status(200).send("Property Deleted Successfully");
    } catch (error) {
        console.log(error);
        res.status(500).send("Internal Server Error");
    }
});

router.get("/category", async (req, res) => {
    const { category } = req.query;
    try {
        // Ensure category is provided and valid
        if (!category) {
            return res.status(400).json({ error: 'Category query parameter is required' });
        }

        const properties = await Property.find({ category })
            .populate('category'); // Populate category if needed
        res.json(properties);
    } catch (error) {
        res.status(500).json({ error: 'Error fetching properties' });
    }
})


//Property and USer route for Dashboard

router.get("/properties/user/:userId", async (req, res) => {
    const userId = req.params.userId;
    try {
        //Find propertues by the specific user
        const userProperties = await Property.find({ user: userId });
        res.status(200).json(userProperties)
    } catch (error) {
        console.error('Error fetching user Properties:', error);
        res.status(500).json({ error: 'Server error Fetching user properties ' });
    }
})

module.exports = router;
