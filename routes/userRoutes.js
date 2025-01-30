// routes/userRoutes.js
const router = require("express").Router();
const User = require("../models/User");
const { regValidation } = require("./validation");
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const verifyToken = require('./verifyToken');
const { Property } = require("../models/Property");
require('dotenv').config();
const passport = require('passport');
const { login, register, verifyEmail, resendVerification, LogOut, ForgetPass, ResetPass } = require("../controllers/auth.controller");


router.post('/login', login)

// Registration Route
router.post('/register', register);

router.post('/verify-email', verifyEmail);

router.post('/resend-verfication', resendVerification)

router.post('/logout', LogOut);

router.post('/forget-password', ForgetPass);

router.post('/reset-password/:token', ResetPass);

router.get(
    "/auth/google",
    passport.authenticate("google", { scope: ["profile", "email"] })
)

router.get("/auth/google/callback",
    passport.authenticate("google", { failureRedirect: "/login" }),
    (req, res) => {
        const { profile, isNewUser } = req.user

        if (isNewUser) {
            return res.redirect(`http://localhost:3000/complete-signup?email=${profile.email}`)
        }

        const { user, token } = req.user
        res
            .cookie("token", token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
                sameSite: "strict",
                maxAge: 3600000,
            })
            .redirect("http://localhost:3000/properties")
    }
)

// Complete Google Signup Route
router.post('/complete-google-signup', async (req, res) => {
    try {
        const { email, role, username } = req.body

        if (!['buyer', 'seller', 'admin'].includes(role)) {
            return res.status(400).json({ message: 'Invalid role selected' })
        }

        const existingUser = await User.findOne({ email })
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' })
        }

        const user = new User({
            username,
            email,
            authMethod: 'google',
            isVerified: true,
            role: role
        })

        await user.save()

        const token = jwt.sign(
            {
                email: user.email,
                id: user._id,
                role: user.role
            },
            process.env.TOKEN_SECRET,
            { expiresIn: "1h" }
        )

        res
            .cookie('token', token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
                sameSite: "strict",
                maxAge: 3600000,
            })
            .json({
                message: 'Profile completed successfully',
                user: {
                    id: user._id,
                    username: user.username,
                    email: user.email,
                    role: user.role
                }
            })
    } catch (error) {
        console.error(error)
        res.status(500).json({ message: 'Error completing profile' })
    }
})

router.get("/profile", (req, res) => {
    const token = req.cookies.token;

    if (!token) return res.status(403).send("Access Denied");

    jwt.verify(token, process.env.TOKEN_SECRET, (err, decoded) => {
        if (err) return res.status(400).send("Invalid token");
        res.send(decoded);
    });
});

// router.post('/reset-password/:token', async (req, res) => {
//     const { token } = req.params;
//     const { password } = req.body;

//     try {
//         const decoded = jwt.verify(token, tokenSecret);

//         const user = await User.findOne({
//             _id: decoded.id,
//             resetPasswordToken: token,
//             resetPasswordExpires: { $gt: Date.now() }
//         });

//         if (!user) return res.status(400).send('Password reset token is invalid or has expired');

//         user.password = await bcrypt.hash(password, 10);
//         user.resetPasswordToken = undefined;
//         user.resetPasswordExpires = undefined;
//         await user.save();

//         res.status(200).send('Password has been reset');
//     } catch (err) {
//         res.status(500).send('Error on the server');
//     }
// });

router.get('/dashboard', verifyToken, async (req, res) => {
    try {
        const properties = await Property.find({ owner: req.user.userId });
        res.json(properties);
    } catch (error) {
        res.status(400).json({ message: "Error in fetching data" });
    }
});

module.exports = router;
