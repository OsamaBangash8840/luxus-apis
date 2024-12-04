const router = require("express").Router();
const User = require("../models/User");
const { regValidation } = require("./validation")
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const verifyToken = require('./verifyToken');
const { Property } = require("../models/Property");
require('dotenv').config();

router.post('/register', async (req, res) => {
    const { name, email, password, address } = req.body;
    const { error } = regValidation(req.body);
    if (error) return res.send(error.details[0].message);

    const usedEmail = await User.findOne({ email: req.body.email })
    if (usedEmail) return res.status(400).send("Email is already Registered");


    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);

    const user = new User({
        name,
        email,
        password: hash
    })

    try {
        const savedUser = await user.save();
        res.send(savedUser)
    } catch (error) {
        res.status(400).send(error)
    }


})

// const tokenSecret = '12345';
router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    // Find the user by email
    const findedUser = await User.findOne({ email: email });
    if (!findedUser) return res.status(400).send("Email Incorrect");

    // Compare the provided password with the hashed password in the database
    const compare = await bcrypt.compare(password, findedUser.password);
    if (!compare) return res.status(400).send("Password Incorrect");

    // Sign the JWT token with the user's id and email
    const token = jwt.sign(
        { id: findedUser._id},  // Include user id here
        process.env.TOKEN_SECRET,
        { expiresIn: '1h' }  // Optional: token expiration time
    );

    // Return the token in the response header and body
    res.header('token', token).send({ token });
});



router.post('/forget-password', async (req, res) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).send("This email doesn't exist");
        }

        const token = jwt.sign({ id: user._id }, tokenSecret, { expiresIn: '1h' });
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000;
        await user.save();

        const transporter = nodemailer.createTransport({
            service:"gmail",
            host: 'smtp.gmail.com',
            // port: 587,
            auth: {
                user: process.env.EMAIL,
                pass: process.env.APP_PASSWORD
            }
        });

        const mailOptions = {
            to: user.email,
            from: {
                name: 'Real Estate Listing Site',
                email: "info@luxusrealestate.com"
            },
            subject: 'Password Reset',
            text: `This Email is Sent by Real Estate Listing Site
            Please click on the following link, or paste it into your browser to complete the process:\n\n
            https://localhost:3000/reset-password/${token}\n\n
            If you did not request this, please ignore this email and your password will remain unchanged.\n`
        };

        transporter.sendMail(mailOptions, (err, response) => {
            if (err) {
                console.error('Error in sending email:', err); // Log detailed error
                return res.status(500).send('Error in sending email');
            }
            console.log('Email sent successfully to:', user.email);
            res.status(200).send('Recovery email sent');
        });
    } catch (err) {
        res.status(500).send('Error on the server');
    }

})


router.post('/reset-password/:token', async (req, res) => {
    const { token } = req.params;
    const { password } = req.body;

    try {
        console.log('Received reset-password request');
        console.log('Token:', token);
        
        const decoded = jwt.verify(token, tokenSecret);
        console.log('Decoded token:', decoded);

        const user = await User.findOne({
            _id: decoded.id,
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) {
            console.log('No user found or token expired');
            return res.status(400).send('Password reset token is invalid or has expired');
        }

        console.log('User found:', user);

        user.password = await bcrypt.hash(password, 10);
        console.log('Password hashed');

        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();
        console.log('User saved');

        res.status(200).send('Password has been reset');
    } catch (err) {
        console.error('Error during password reset:', err);
        res.status(500).send('Error on the server');
    }
});

router.get('/dashboard',verifyToken, async (req, res) => {
   try {
    const properties = await Property.find({owner:req.user.userId});
    res.json(properties);
   } catch (error) {
    res.status(400).json({
        "message":"Error in fetching data"
    })
   }
  });

module.exports = router;