const jwt = require('jsonwebtoken');
require("dotenv").config();

const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];

  console.log('Authorization Header:', authHeader);

  if (!authHeader) return res.status(403).send('Access denied.');

  const token = authHeader.split(' ')[1];

  if (!token) return res.status(403).send('Access denied.');

  try {
    const verified = jwt.verify(token, process.env.TOKEN_SECRET);
    req.user = verified;
    console.log('Verified User:', req.user);
    next();
  } catch (error) {
    res.status(400).send('Invalid token.');
  }
};

module.exports = verifyToken;
