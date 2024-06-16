const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
require('dotenv').config();


// Email
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USERNAME,
        pass: process.env.EMAIL_PASSWORD
    }
});

const generateVerificationToken = (email) => {
    return jwt.sign(
        { email: email },
        process.env.JWT_SECRET, // Replace with your own secret key for signing the token
        { expiresIn: '120m' } // Token expires in 10 minutes
    );
};

// Functions
function validatePassword(password) {
    // Password must be at least 8 characters long
    if (password.length < 8) {
        return false;
    }
    
    // Check for at least one special character, one lowercase letter, one uppercase letter, and one number
    const regex = /^(?=.*\d)(?=.*[!@#$%^&*])(?=.*[a-z])(?=.*[A-Z]).{8,}$/;
    return regex.test(password);
}
function honeypotCheck(address) {
    if (address.length > 0) {
        return false;
    }
    return true;
}

// Routes
router.get('/', (req, res) => {
    res.render('index', { messages: { error: req.flash('error_msg'), success: req.flash('success_msg') } });
});



//User Services
router.get('/login', (req, res) => {
    res.render('index', { messages: { error: req.flash('error_msg'), success: req.flash('success_msg') } });
});
router.get('/signup', (req, res) => {
    res.render('signup', { messages: { error: req.flash('error_msg'), success: req.flash('success_msg') } });
});
router.post('/signup', async  (req, res) => {
    const { firstName, lastName, email, birthdate, password, confirmPassword, address } = req.body;

    if (password !== confirmPassword) {
        req.flash('error_msg', 'Passwords do not match.');
        return res.redirect('/signup');
    }

    if (!validatePassword(password)) {
        req.flash('error_msg', 'Password must be at least 8 characters long and contain at least one special character, one lowercase letter, one uppercase letter, and one number.');
        return res.redirect('/signup');
    }

    if(!honeypotCheck(address)){
        req.flash('error_msg', 'An error occurred.');
        return res.redirect('/signup');
    }

    try {
        const db = req.app.locals.db;
        const existingUser = await db.collection('user').findOne({ email });

        if (existingUser) {
            req.flash('error_msg', 'Email already registered.');
            return res.redirect('/signup');
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const token = generateVerificationToken(email);

        const newUser = {
            firstName,
            lastName,
            email,
            birthdate: new Date(birthdate),
            password: hashedPassword,
            token: token,
            verified: false
        };

        await db.collection('user').insertOne(newUser);

        

        // Send verification email
        const mailOptions = {
            from: process.env.EMAIL_USERNAME,
            to: email,
            subject: 'Habitica: Email Verification',
            text: `Hi ${firstName} ${lastName},\n\n`
                  + `Thank you for signing up on our website. Please click on the following link to verify your email:\n`
                  + `http://localhost:3000/verify/${token}\n\n`
                  + `If you did not sign up for our service, please ignore this email.\n`
                  + `Regards,\nHabitica`
        };

        await transporter.sendMail(mailOptions);
        req.flash('success_msg', 'Please check your email for verification instructions.');
        res.redirect('/login'); // Redirect to login page after successful signup

    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Something went wrong.');
        res.redirect('/signup');
    }
});

// Verify route to handle email verification
router.get('/verify/:token', async (req, res) => {
    const token = req.params.token;
    const db = req.app.locals.db;
    try {
        // Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Find user in MongoDB and update verified status
        const userEmail = decoded.email;
        const user = await db.collection('user').findOneAndUpdate(
            { email: userEmail },
            { $set: { verified: true } }
        );

        req.flash('success_msg', 'Email verification successful. You can now log in.');
        res.redirect('/login'); // Redirect to login page after successful verification

    } catch (error) {
        console.error('Error verifying token:', error);
        req.flash('error_msg', 'Invalid or expired token. Please request a new verification email.');
        res.redirect('/login'); // Redirect to login page or handle as needed
    }
});

module.exports = router;