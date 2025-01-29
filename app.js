// server.js (Express)
const express = require('express');
const connectDB = require('./config/db');
const userRoutes = require('./routes/userRoutes');
const propertyRoutes = require('./routes/propertyRoutes');
const categoryRoutes = require('./routes/categoryRoutes');
const tourRoutes = require('./routes/schedulaTourRoutes');
const reviewRoute = require('./routes/reviewsRoutes');
const contactForm = require('./routes/contactForm');
const PORT = 8000 || process.env.PORT
const multer = require('multer');
const path = require('path');
const cors = require('cors');
const passport = require('./routes/googleRoutes');
const session = require('express-session')
var cookieParser = require('cookie-parser')
require('dotenv').config();

const app = express();
app.use(express.json());

app.use(
  session({
    secret: process.env.TOKEN_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
  })
)

// Middleware
app.use(cookieParser())
app.use(cors({ exposedHeaders: ['Content-Length', 'Authorization', 'token'], origin: 'http://localhost:3000', credentials: true }));

// Connect to database
connectDB();
app.use((req, res, next) => {
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin-allow-popups", "Access-Control-Allow-Origin");
  next();
});


// Routes
app.use('/api', userRoutes);
app.use('/api', propertyRoutes);
app.use('/api', categoryRoutes);
app.use('/api', tourRoutes);
app.use('/api', reviewRoute);
app.use('/api', contactForm)
app.use(passport.initialize());



app.get('/', (req, res) => {
  res.send('Hello, world!');
});

// Multer setup for file uploads
// Configure Multer storage
// Set up storage configuration with multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/'); // Ensure the 'uploads/' directory exists
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname)); // Name file with timestamp and extension
  },
});

// Initialize multer with the storage configuration
const upload = multer({ dest: 'uploads/' });

// Serve static files from 'uploads' directory
app.use('/uploads', express.static('uploads'));

// Upload route to handle file upload
app.post('/api/upload', upload.array('files'), (req, res) => {
  console.log('Files received:', req.files); // Should print files details
  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ error: 'No files uploaded' });
  }

  try {
    const uploadedImageUrls = req.files.map((file) => ({
      imageUrl: `${req.protocol}://${req.get('host')}/uploads/${file.filename}`,
    }));

    res.status(200).json(uploadedImageUrls);
  } catch (err) {
    console.error('Error processing files:', err);
    res.status(500).json({ error: 'Failed to process uploaded files' });
  }
});


app.listen(PORT, () => {
  console.log("API IS RUNNING ON 8000")
})

// Export app
module.exports = app;
