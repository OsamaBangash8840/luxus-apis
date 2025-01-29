const SchedulaTour = require('../models/SchedulaTour');
require('dotenv').config();
const router = require('express').Router();
const nodemailer = require('nodemailer'); // Ensure you import nodemailer

router.post('/schedule-tour', async (req, res) => {
    const { name, email, phone, date, message } = req.body;

    try {
        // Validate booking time
        const bookingTime = new Date(date).getHours();
        if (bookingTime >= 23 || bookingTime < 6) {
            return res.status(400).json({ error: 'Booking is not allowed between 11:00 PM and 6:00 AM' });
        }

        const tour = new SchedulaTour({
            name,
            email,
            phone,
            date,
            message,
        });

        // Save the tour to the database
        await tour.save();

        // Configure email transporter
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
                email: 'info@luxusrealestate.com',
            },
            subject: 'New Tour Submission',
            text: `This Email is Sent by Luxus Real Estate
You have a new contact tour form submission:\n\n
Name: ${name}\n
Email: ${email}\n
Date: ${date}\n
Phone: ${phone}\n
Message: ${message}`,
        };

        // Email to user
        const userMailOptions = {
            to: email,
            from: {
                name: 'Luxus Real Estate',
                email: 'info@luxusrealestate.com',
            },
            subject: 'Tour Confirmation',
            text: `Dear ${name},\n\n
Thank you for scheduling a tour with Luxus Real Estate.\n
Here are your booking details:\n\n
Date: ${new Date(date).toLocaleString()}\n
Phone: ${phone}\n
Message: ${message}\n\n
We look forward to seeing you!\n\n
Best regards,\n
Luxus Real Estate Team`,
        };

        // Send emails
        await transporter.sendMail(adminMailOptions);
        await transporter.sendMail(userMailOptions);

        console.log('Emails sent successfully');
        return res.status(200).json({ message: 'Tour Added Successfully and emails sent' });
    } catch (error) {
        console.error('Error in scheduling tour:', error);
        return res.status(500).json({ error: 'Error in scheduling tour' });
    }
});

module.exports = router;