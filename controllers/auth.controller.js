const { sendVerificationEmail, generateAuthToken } = require("../helpers/auth.helper");
const User = require("../models/User");
const bcrypt = require('bcryptjs');
require('dotenv').config();




module.exports.login = async (req, res) => {
    // console.log('Request Body:', req.body); // Log the request body

    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required' });
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: "Invalid email " });
        }

        if (!user.isVerified) {
            await sendVerificationEmail(user);
            return res.status(403).json({
                message: 'Email not verified. A new verification link has been sent.',
                needsVerification: true
            });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ message: "Invalid email or password" });
        }

        const token = generateAuthToken(user);

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
            maxAge: 3600000,
        }).json({
            token,
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                role: user.role,
            }
        });
    } catch (error) {
        console.error('Error in login route:', error);
        res.status(500).json({ message: 'An error occurred. Please try again later.' });
    }
};


module.exports.register = async (req, res) => {
    // console.log('Full request object:', req)
    // console.log('Request body:', req.body)
    // console.log('Content-Type:', req.headers['content-type'])
    const { username, email, password, role } = req.body;

    if (!username || !email || !password || !role) {
        return res.status(400).json({
            message: 'All fields are required.',
            fields: { username, email, password, role },
        });
    }

    const existingUser = await User.findOne({
        $or: [{ email }, { username }]
    });

    if (existingUser) {
        return res.status(400).json({
            message: existingUser.email === email ?
                'Email already registered' :
                'Username already taken'
        });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = new User({
        username,
        email,
        password: hashedPassword,
        role,
        authMethod: 'local',
        isVerified: false
    });

    await user.save();

    const token = generateAuthToken(user);

    try {
        await sendVerificationEmail(user);

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
            maxAge: 3600000,
        }).status(201).json({
            message: 'Registration successful. Please check your email to verify.',
            userId: user._id
        });
    } catch (error) {
        res.status(201).json({
            message: 'Account created but verification email failed to send. Please try resending verification email.',
            userId: user._id
        });
    }
};