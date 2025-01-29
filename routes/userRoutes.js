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
const { login, register } = require("../controllers/auth.controller");

const tokenSecret = process.env.TOKEN_SECRET;

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL,
        pass: process.env.APP_PASSWORD
    }
});

const generateVerificationToken = (userId) => {
    if (!process.env.VERIFICATION_SECRECT) {
        throw new Error('VERIFICATION_SECRET not configured');
    }
    return jwt.sign({ id: userId }, process.env.VERIFICATION_SECRECT, {
        expiresIn: '1h'
    });
};

const generateAuthToken = (user) => {
    if (!process.env.TOKEN_SECRET) {
        throw new Error('TOKEN_SECRET not configured');
    }
    return jwt.sign(
        { email: user.email, id: user._id, role: user.role },
        process.env.TOKEN_SECRET,
        { expiresIn: "1h" }
    );
};

const sendVerificationEmail = async (user) => {
    try {
        const verificationToken = generateVerificationToken(user._id);

        // Update user with verification token
        user.verificationToken = verificationToken;
        user.verificationTokenExpires = Date.now() + 3600000; // 1 hour
        await user.save();

        const verificationLink = `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}`;

        const mailOptions = {
            from: process.env.EMAIL,
            to: user.email,
            subject: 'Verify Your Email',
            html: `
                <div style="max-width: 600px; margin: 0 auto; padding: 20px; font-family: Arial, sans-serif;">
                    <h2 style="color: #333; text-align: center;">Email Verification</h2>
                    <p style="color: #666;text-align: center">Please click the button below to verify your email address:</p>
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="${verificationLink}" 
                           style="background-color: #4CAF50; 
                                  color: white; 
                                  padding: 12px 30px; 
                                  text-decoration: none; 
                                  border-radius: 5px;
                                  display: inline-block;">
                            Verify Email
                        </a>
                    </div>
                    <p style="color: #666; font-size: 14px;">This link will expire in 1 hour.</p>
                    <p style="color: #999; font-size: 12px;">If the button doesn't work, you can copy and paste this link into your browser:</p>
                    <p style="color: #666; font-size: 12px; word-break: break-all;">${verificationLink}</p>
                </div>
            `
        };

        await transporter.sendMail(mailOptions);
        return true;
    } catch (error) {
        console.error('Email sending failed:', error);
        throw new Error('Failed to send verification email');
    }
};

router.post('/login', login)

// Registration Route
router.post('/register', register);
// router.post('/register', async (req, res) => {
//     // console.log('Full request object:', req)
//     // console.log('Request body:', req.body)
//     // console.log('Content-Type:', req.headers['content-type'])
//     const { username, email, password, role } = req.body;

//     if (!username || !email || !password || !role) {
//         return res.status(400).json({
//             message: 'All fields are required.',
//             fields: { username, email, password, role },
//         });
//     }

//     const existingUser = await User.findOne({
//         $or: [{ email }, { username }]
//     });

//     if (existingUser) {
//         return res.status(400).json({
//             message: existingUser.email === email ?
//                 'Email already registered' :
//                 'Username already taken'
//         });
//     }

//     const salt = await bcrypt.genSalt(10);
//     const hashedPassword = await bcrypt.hash(password, salt);

//     const user = new User({
//         username,
//         email,
//         password: hashedPassword,
//         role,
//         authMethod: 'local',
//         isVerified: false
//     });

//     await user.save();

//     const token = generateAuthToken(user);

//     try {
//         await sendVerificationEmail(user);

//         res.cookie('token', token, {
//             httpOnly: true,
//             secure: process.env.NODE_ENV === "production",
//             sameSite: "strict",
//             maxAge: 3600000,
//         }).status(201).json({
//             message: 'Registration successful. Please check your email to verify.',
//             userId: user._id
//         });
//     } catch (error) {
//         res.status(201).json({
//             message: 'Account created but verification email failed to send. Please try resending verification email.',
//             userId: user._id
//         });
//     }
// });

// Login Route
// router.post('/login', async (req, res) => {
//     // console.log('Request Body:', req.body); // Log the request body

//     const { email, password } = req.body;

//     if (!email || !password) {
//         return res.status(400).json({ message: 'Email and password are required' });
//     }

//     try {
//         const user = await User.findOne({ email });
//         if (!user) {
//             return res.status(400).json({ message: "Invalid email " });
//         }

//         if (!user.isVerified) {
//             await sendVerificationEmail(user);
//             return res.status(403).json({
//                 message: 'Email not verified. A new verification link has been sent.',
//                 needsVerification: true
//             });
//         }

//         const validPassword = await bcrypt.compare(password, user.password);
//         if (!validPassword) {
//             return res.status(400).json({ message: "Invalid email or password" });
//         }

//         const token = generateAuthToken(user);

//         res.cookie('token', token, {
//             httpOnly: true,
//             secure: process.env.NODE_ENV === "production",
//             sameSite: "strict",
//             maxAge: 3600000,
//         }).json({
//             token,
//             user: {
//                 id: user._id,
//                 username: user.username,
//                 email: user.email,
//                 role: user.role,
//             }
//         });
//     } catch (error) {
//         console.error('Error in login route:', error);
//         res.status(500).json({ message: 'An error occurred. Please try again later.' });
//     }
// });

// Email Verification Route


router.post('/verify-email', async (req, res) => {
    // console.log("Request Body:", req.body); // Debugging log

    const { token } = req.body;

    if (!token) {
        return res.status(400).json({ message: "Verification token is required" });
    }

    try {
        console.log("Token received:", token); // Debugging log

        const decoded = jwt.verify(token, process.env.VERIFICATION_SECRECT);
        // console.log("Decoded Token:", decoded); // Debugging log

        const user = await User.findOne({
            _id: decoded.id,
            verificationToken: token,
            verificationTokenExpires: { $gt: Date.now() }
        });

        // console.log("User found:", user); // Debugging log

        if (!user) {
            return res.status(400).json({ message: "Invalid or expired token" });
        }

        user.isVerified = true;
        user.verificationToken = undefined;
        user.verificationTokenExpires = undefined;
        await user.save();

        res.json({ message: "Email verified successfully" });
    } catch (error) {
        console.error("Error verifying email:", error);

        if (error.name === "JsonWebTokenError") {
            return res.status(400).json({ message: "Invalid token" });
        }

        res.status(500).json({ message: "An error occurred. Please try again later." });
    }
});



// Resend Verification Route
router.post('/resend-verification', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ message: 'Email is required' });
    }

    try {
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        if (user.isVerified) {
            return res.status(400).json({ message: 'Email is already verified' });
        }

        const lastEmailSent = user.verificationTokenExpires || 0;
        const cooldownPeriod = 5 * 60 * 1000; // 5 minutes

        if (lastEmailSent && Date.now() - lastEmailSent < cooldownPeriod) {
            return res.status(429).json({
                message: 'Please wait before requesting another verification email',
                retryAfter: Math.ceil((cooldownPeriod - (Date.now() - lastEmailSent)) / 1000)
            });
        }

        await sendVerificationEmail(user);
        res.json({ message: 'Verification email sent successfully' });
    } catch (error) {
        console.error('Error in resend verification route:', error);
        res.status(500).json({ message: 'Failed to send verification email' });
    }
});


// Complete Google Signup Route
router.get(
    "/auth/google",
    passport.authenticate("google", { scope: ["profile", "email"] })
)

router.get(
    "/auth/google/callback",
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

router.post('/logout', (req, res) => {
    res.clearCookie('token');
    res.status(200).send({ message: 'Logged out successfully' });
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
            service: "gmail",
            host: 'smtp.gmail.com',
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
            text: `Please click on the following link, or paste it into your browser to complete the process:\n\n
      https://localhost:3000/reset-password/${token}\n\n
      If you did not request this, please ignore this email.`
        };

        transporter.sendMail(mailOptions, (err, response) => {
            if (err) {
                console.error('Error in sending email:', err);
                return res.status(500).send('Error in sending email');
            }
            res.status(200).send('Recovery email sent');
        });
    } catch (err) {
        res.status(500).send('Error on the server');
    }
});

router.post('/reset-password/:token', async (req, res) => {
    const { token } = req.params;
    const { password } = req.body;

    try {
        const decoded = jwt.verify(token, tokenSecret);

        const user = await User.findOne({
            _id: decoded.id,
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() }
        });

        if (!user) return res.status(400).send('Password reset token is invalid or has expired');

        user.password = await bcrypt.hash(password, 10);
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();

        res.status(200).send('Password has been reset');
    } catch (err) {
        res.status(500).send('Error on the server');
    }
});

router.get('/dashboard', verifyToken, async (req, res) => {
    try {
        const properties = await Property.find({ owner: req.user.userId });
        res.json(properties);
    } catch (error) {
        res.status(400).json({ message: "Error in fetching data" });
    }
});

module.exports = router;
