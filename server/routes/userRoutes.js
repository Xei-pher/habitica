const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const axios = require('axios');
require('dotenv').config();

const isLoggedIn = require('../middleware/isLoggedIn');

const recaptchaSiteKey = process.env.RECAPTCHA_SITEKEY;
const recaptchaSecretKey = process.env.RECAPTCHA_SECRET;

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
        process.env.JWT_SECRET,
        { expiresIn: '120m' }
    );
};

// Functions
function validatePassword(password) {
    if (password.length < 8) {
        return false;
    }
    const regex = /^(?=.*\d)(?=.*[!@#$%^&*])(?=.*[a-z])(?=.*[A-Z]).{8,}$/;
    return regex.test(password);
}

function honeypotCheck(address) {
    return address;
}

async function verifyRecaptcha(token) {
    try {
        const response = await axios.post(`https://www.google.com/recaptcha/api/siteverify`, null, {
            params: {
                secret: recaptchaSecretKey,
                response: token
            }
        });
        return response.data.success;
    } catch (error) {
        console.error('Error verifying reCAPTCHA:', error);
        return false;
    }
}

// Main Route
router.get('/', (req, res) => {
    if (req.session.userId) {
        res.redirect('/home');
    } else {
        res.render('index', {
            messages: {
                error: req.flash('error_msg'),
                success: req.flash('success_msg')
            },
            sitekey: recaptchaSiteKey
        });
    }
});

// User Services
router.get('/login', (req, res) => {
    if (req.session.userId) {
        res.redirect('/home');
    } else {
        res.render('index', {
            messages: {
                error: req.flash('error_msg'),
                success: req.flash('success_msg')
            },
            sitekey: recaptchaSiteKey
        });
    }
});

router.get('/forgot-password', (req, res) => { 
    res.render('forgotpassword');
});

router.post('/reset-password', async (req, res) => { 
    const db = req.app.locals.db;
    const { email } = req.body;
    const token = generateVerificationToken(email);

    try {
        const user = await db.collection('user').findOne({ email });

        if (!user) {
            req.flash('error_msg', 'Invalid credentials.');
            return res.redirect('/login');
        }
        if (!user.verified) {
            req.flash('error_msg', 'Please verify your email first.');
            return res.redirect('/login');
        }

        const mailOptions = {
            from: process.env.EMAIL_USERNAME,
            to: email,
            subject: 'Habitica: Password Reset',
            text: `Hi,\n\n`
                  + `Please click on the following link to reset your password on Habitica:\n`
                  + `http://localhost:3000/resetpassword/${token}\n\n`
                  + `If you did not sign up for our service, please ignore this email.\n`
                  + `Regards,\nHabitica`
        };
    
        await transporter.sendMail(mailOptions);
        res.render('passwordreset');

    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Something went wrong.');
        res.redirect('/login');
    }
});

router.get('/resetpassword/:token', async (req, res) => {
    const token = req.params.token;
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        res.render('resetpassword', { 
            messages: {
                error: req.flash('error_msg'),
                success: req.flash('success_msg')
            }, 
            token 
        });
    } catch (error) {
        console.error('Error regarding token:', error);
        req.flash('error_msg', 'Invalid or expired token. Please request a password reset email.');
        res.redirect('/login');
    }
});

router.post('/resetpassword/:token', async (req, res) => {
    const token = req.params.token;
    const db = req.app.locals.db;
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        const userEmail = decoded.email;
        const user = await db.collection('user').findOne({ email: userEmail });
        if (!user) {
            req.flash('error_msg', 'User not found.');
            return res.redirect('/login');
        }

        const { password, confirmPassword } = req.body;
        if (password !== confirmPassword) {
            req.flash('error_msg', 'Passwords do not match.');
            return res.redirect(`/resetpassword/${token}`);
        }

        if (!validatePassword(password)) {
            req.flash('error_msg', 'Invalid password.');
            return res.redirect(`/resetpassword/${token}`);
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await db.collection('user').findOneAndUpdate(
            { email: userEmail },
            { $set: { password: hashedPassword } }
        );

        req.flash('success_msg', 'Password reset successful.');
        res.redirect('/login');
    } catch (error) {
        console.error('Error regarding token:', error);
        req.flash('error_msg', 'Invalid or expired token.');
        res.redirect('/login');
    }
});

router.get('/signup', (req, res) => {
    if (req.session.userId) {
        res.redirect("/home");
    } else {
        res.render('signup', {
            messages: {
                error: req.flash('error_msg'),
                success: req.flash('success_msg')
            },
            sitekey: recaptchaSiteKey
        });
    }
});

router.post('/login', async (req, res) => {
    const { email, password, 'g-recaptcha-response': recaptchaToken } = req.body;
    const db = req.app.locals.db;
    const recaptchaVerified = await verifyRecaptcha(recaptchaToken);
    if (!recaptchaVerified) {
        req.flash('error_msg', 'reCAPTCHA verification failed. Please try again.');
        return res.redirect('/login');
    }

    try {
        const user = await db.collection('user').findOne({ email });

        if (!user) {
            req.flash('error_msg', 'Invalid credentials.');
            return res.redirect('/login');
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            req.flash('error_msg', 'Invalid credentials.');
            return res.redirect('/login');
        }

        if (!user.verified) {
            req.flash('error_msg', 'Please verify your email first.');
            return res.redirect('/login');
        }
        req.session.fname = user.firstName;
        req.session.userId = user._id;
        req.session.save(() => {
            res.redirect('/home');
        });
    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Something went wrong.');
        res.redirect('/login');
    }
});

router.post('/signup', async (req, res) => {
    const { email, password, confirmPassword, address, 'g-recaptcha-response': recaptchaToken } = req.body;
    const db = req.app.locals.db;

    if (!await verifyRecaptcha(recaptchaToken)) {
        req.flash('error_msg', 'reCAPTCHA verification failed. Please try again.');
        return res.redirect('/signup');
    }

    if (password !== confirmPassword) {
        req.flash('error_msg', 'Passwords do not match.');
        return res.redirect('/signup');
    }

    if (!validatePassword(password)) {
        req.flash('error_msg', 'Password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, one digit, and one special character.');
        return res.redirect('/signup');
    }

    if (honeypotCheck(address)) {
        req.flash('error_msg', 'Spam detected.');
        return res.redirect('/signup');
    }

    try {
        const existingUser = await db.collection('user').findOne({ email });
        if (existingUser) {
            req.flash('error_msg', 'Email already registered.');
            return res.redirect('/signup');
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const token = generateVerificationToken(email);

        const newUser = {
            email,
            password: hashedPassword,
            verified: false,
            createdAt: new Date()
        };

        await db.collection('user').insertOne(newUser);

        const mailOptions = {
            from: process.env.EMAIL_USERNAME,
            to: email,
            subject: 'Habitica: Email Verification',
            text: `Hi,\n\n`
                  + `Please click on the following link to verify your email address on Habitica:\n`
                  + `http://localhost:3000/verify-email/${token}\n\n`
                  + `If you did not sign up for our service, please ignore this email.\n`
                  + `Regards,\nHabitica`
        };

        await transporter.sendMail(mailOptions);
        req.flash('success_msg', 'Signup successful! Please check your email to verify your account.');
        res.redirect('/signup');
    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Something went wrong.');
        res.redirect('/signup');
    }
});

router.get('/verify-email/:token', async (req, res) => {
    const token = req.params.token;
    const db = req.app.locals.db;
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const email = decoded.email;

        const user = await db.collection('user').findOne({ email });
        if (!user) {
            req.flash('error_msg', 'User not found.');
            return res.redirect('/signup');
        }

        if (user.verified) {
            req.flash('success_msg', 'Email already verified. You can log in now.');
            return res.redirect('/login');
        }

        await db.collection('user').updateOne({ email }, { $set: { verified: true } });
        req.flash('success_msg', 'Email verified successfully. You can log in now.');
        res.redirect('/login');
    } catch (err) {
        console.error('Error verifying email:', err);
        req.flash('error_msg', 'Invalid or expired token.');
        res.redirect('/signup');
    }
});

router.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error(err);
            req.flash('error_msg', 'Could not log out. Please try again.');
            res.redirect('/home');
        } else {
            res.redirect('/login');
        }
    });
});

module.exports = router;
