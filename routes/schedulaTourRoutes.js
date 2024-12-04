const SchedulaTour = require('../models/SchedulaTour');
require('dotenv').config();
const router = require('express').Router();
const nodemailer = require('nodemailer'); // Ensure you import nodemailer

router.post('/schedule-tour', async (req, res) => {
    const { name, email, phone, date, message } = req.body;

    const tour = new SchedulaTour({
        name,
        email,
        phone,
        date,
        message
    });

    try {
        await tour.save();

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            host: 'smtp.gmail.com',
            auth: {
                user: process.env.EMAIL,
                pass: process.env.APP_PASSWORD,
            },
        });

        const mailOptions = {
            to: process.env.EMAIL,
            from: {
                name: 'Luxus Real Estate',
                email: 'info@luxusrealestate.com',
            },
            subject: 'Tour Submission',
            text: `This Email is Sent by Luxus Real Estate
            You have a new contact tour form submission:\n\nName: ${name}\nEmail: ${email} \nDate : ${date}\nNumber : ${phone}\nMessage: ${message}`,
        };

        transporter.sendMail(mailOptions, (err, response) => {
            if (err) {
                console.error('Error in sending email:', err); // Log detailed error
                return res.status(500).json({ error: 'Error in sending email' });
            }
            console.log('Email sent successfully to:', process.env.EMAIL);
            return res.status(200).json({ message: 'Tour Added Successfully and email sent' });
        });
    } catch (error) {
        console.error('Error in scheduling tour:', error); // Log detailed error
        res.status(400).json({ error: 'Error in scheduling tour' });
    }
});

module.exports = router;
