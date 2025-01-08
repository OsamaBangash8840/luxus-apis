const { check, validationResult } = require('express-validator');
const Contact = require('../models/Contact');
const nodemailer = require('nodemailer');
const Newsletter = require('../models/Newsletter');
const router = require('express').Router();
require('dotenv').config();

router.post(
    '/submit',
    [
        check('name', 'Full name is required').not().isEmpty(),
        check('email', 'Invalid email address').isEmail(),
        check('mobile', 'Invalid mobile number').matches(/^\+?[0-9 ]{10,15}$/),
        check('message', 'Message is required').not().isEmpty(),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { name, email, message, mobile } = req.body;

        const submission = new Contact({ name, email, message, mobile });

        try {
            await submission.save();

            const transporter = nodemailer.createTransport({
                service: 'gmail',
                host: 'smtp.gmail.com',
                auth: {
                    user: process.env.EMAIL,
                    pass: process.env.APP_PASSWORD,
                },
            });

            // Email to admin
            const adminMailOptions = {
                to: process.env.EMAIL,
                from: {
                    name: 'Luxus Real Estate',
                    email: 'hello@luxusrealestate.com',
                },
                subject: 'Form Submission',
                text: `This Email is Sent by Luxus Real Estate
      You have a new contact form submission:\n\nName: ${name}\nEmail: ${email}\nNumber: ${mobile}\nMessage: ${message}`,
            };

            // Email to user
            const userMailOptions = {
                to: email,
                from: {
                    name: 'Luxus Real Estate',
                    email: 'info@luxusrealestate.com',
                },
                subject: 'Thank you for contacting us!',
                text: `Dear ${name},

      Thank you for reaching out to us. We have received your message and will get back to you shortly.

      Here are the details you submitted:
      Name: ${name}
      Email: ${email}
      Number: ${mobile}
      Message: ${message}

      Best regards,
      BlogsSpot ICP`,
            };

            // Sending emails
            await transporter.sendMail(adminMailOptions);
            await transporter.sendMail(userMailOptions);

            res.status(200).json({ message: 'Form Submitted' });
        } catch (error) {
            console.error('Error in form submission or sending email:', error);
            res.status(500).json({ message: 'Error in form submission or email sending' });
        }
    }
);



router.post('/newsletter', async (req, res) => {
    const { email } = req.body;

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ message: 'Invalid email address' });
    }

    try {
        const newsletter = new Newsletter({ email });

        const existingSubscription = await Newsletter.findOne({ email });
        if (existingSubscription) {
            return res.status(409).json({ message: 'Email is already subscribed' });
        }

        await newsletter.save();

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            host: 'smtp.gmail.com',
            auth: {
                user: process.env.EMAIL,
                pass: process.env.APP_PASSWORD,
            },
        });

        const adminMailOptions = {
            to: process.env.EMAIL,
            from: 'info@luxusrealestate.com',
            subject: 'New Newsletter Subscription',
            text: `You have a new subscription: ${email}`,
        };

        const userMailOptions = {
            to: email,
            from: 'hello@luxusrealestate.com',
            subject: 'Thank You for Subscribing!',
            text: 'Thank you for subscribing to Luxus Real Estate.',
        };

        await transporter.sendMail(adminMailOptions);
        await transporter.sendMail(userMailOptions);

        res.status(200).json({ message: 'Subscription successful!' });
    } catch (error) {
        console.error('Error during subscription:', error);
        res.status(500).json({
            message: 'An error occurred. Please try again later.',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined,
        });
    }
});



module.exports = router;
