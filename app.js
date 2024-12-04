const express = require('express');
const connectDB = require('./config/db');
const userRoutes = require('./routes/userRoutes');
const propertyRoutes = require('./routes/propertyRoutes');
const categoryRoutes = require('./routes/categoryRoutes');
const tourRoutes = require('./routes/schedulaTourRoutes');
const reviewRoute = require('./routes/reviewsRoutes');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
require('dotenv').config();

const PORT = process.env.PORT || 8000;
const app = express();

// Middleware
app.use(express.json());
app.use(cors({ exposedHeaders: ['Content-Length', 'Authorization', 'token'], origin: 'http://localhost:3000', credentials: true }));

// Connect to database
connectDB();

// Routes
app.use('/api', userRoutes);
app.use('/api', propertyRoutes);
app.use('/api', categoryRoutes);
app.use('/api', tourRoutes);
app.use('/api', reviewRoute);


app.get('/', (req, res) => {
  res.send('Hello, world!');
});

// Multer setup for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/'); // Save files to 'uploads' directory
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname)); // Name the file uniquely with timestamp
  }
});

const upload = multer({ storage });

// Upload route
app.post('/api/upload', upload.array('files'), (req, res) => {
  try {
    const uploadedImageUrls = req.files.map(file => {
      return { imageUrl: `http://localhost:${PORT}/uploads/${file.filename}` }; // Correct public URL
    });
    res.status(200).json(uploadedImageUrls);
  } catch (err) {
    console.error('Error uploading images:', err);
    res.status(500).send({ error: 'Failed to upload images' });
  }
});

// Serve static files from 'uploads' directory
app.use('/uploads', express.static('uploads'));

// Start server
app.listen(PORT, () => {
  console.log(`API IS RUNNING ON PORT ${PORT}`);
});
