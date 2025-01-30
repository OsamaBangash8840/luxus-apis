const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
require('dotenv').config();


const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL,
        pass: process.env.APP_PASSWORD
    }
});

module.exports.generateVerificationToken = (userId) => {
    if (!process.env.VERIFICATION_SECRECT) {
        throw new Error('VERIFICATION_SECRET not configured');
    }
    return jwt.sign({ id: userId }, process.env.VERIFICATION_SECRECT, {
        expiresIn: '1h'
    });
};

module.exports.generateAuthToken = (user) => {
    if (!process.env.TOKEN_SECRET) {
        throw new Error('TOKEN_SECRET not configured');
    }
    return jwt.sign(
        { email: user.email, id: user._id, role: user.role },
        process.env.TOKEN_SECRET,
        { expiresIn: "1h" }
    );
};

module.exports.sendVerificationEmail = async (user) => {
    try {
        const verificationToken = this.generateVerificationToken(user._id);

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