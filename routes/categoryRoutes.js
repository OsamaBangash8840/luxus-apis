const { default: mongoose } = require('mongoose');
const { Category } = require('../models/Property');

const router = require('express').Router();


router.post('/categories', async (req, res) => {
    const { name, images } = req.body;
    try {
        const category = new Category({
            name,
            images
        });
        const newCategory = await category.save();
        res.status(200).send(newCategory);
    } catch (error) {
        res.status(400).send(error);
    }
});

router.get('/categories', async(req,res)=>{
    try {
       const allCategories = await Category.find({});
       res.status(200).send(allCategories)
    } catch (error) {
        res.status(error)
    }
})

router.get('/categories/:id', async(req,res)=>{
    const categoryId = req.params.id;

    try {
        const isValidObjectId = mongoose.Types.ObjectId.isValid(categoryId);
        if(!isValidObjectId){
            res.status(400).send("Invalid Id")
        }
        const category = await Category.findById(categoryId);
        if(!category){
            res.status(404).send("Category Not Found")
        }
        res.status(200).send(category)
    } catch (error) {
        res.status(500).send(error)
    }
})

// Fetch properties by category ID
router.get('/properties/category/:categoryId', async (req, res) => {
    try {
      const properties = await Property.find({ category: req.params.categoryId });
      res.json(properties);
    } catch (error) {
      res.status(500).json({ message: 'Server error' });
    }
  });
  

module.exports = router;