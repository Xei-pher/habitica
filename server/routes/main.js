const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const session = require('express-session');
require('dotenv').config();
const axios = require('axios');
const setRateLimit = require("express-rate-limit");
// Rate limit middleware
const rateLimitMiddleware = setRateLimit({
  windowMs: 60 * 1000,
  max: 1000,
  message: "Rate Limit Error",
  headers: true,
});
router.use(rateLimitMiddleware);

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
        process.env.JWT_SECRET, // Replace with your own secret key for signing the token
        { expiresIn: '120m' } // Token expires in 10 minutes
    );
};

// Sessions
router.use(session({
    secret: process.env.SECRET,
    resave:false,
    saveUninitialized: true,
    cookie: {secure:false}
}))

// Functions
function validatePassword(password) {
    // Password Validation
    if (password.length < 8) {
        return false;
    }
    // Check for at least one special character, one lowercase letter, one uppercase letter, and one number
    const regex = /^(?=.*\d)(?=.*[!@#$%^&*])(?=.*[a-z])(?=.*[A-Z]).{8,}$/;
    return regex.test(password);
}
function honeypotCheck(address) {
    // Honeypot Validation For Anti-Bot
    if (address.length > 0) {
        return false;
    }
    return true;
}

function isLoggedIn(req, res, next){
    if(req.session.userId){
        next();
    }
    else{
        req.flash('error_msg', 'Please log in to view this page.');
        res.redirect('/login'); // Redirect to login if not logged in
    }
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
            sitekey: recaptchaSiteKey // Pass the site key to your template
        });
    }
});

//User Services
router.get('/login', (req, res) => {
    if (req.session.userId) {
        res.redirect('/home');
    } else {
        res.render('index', {
            messages: {
                error: req.flash('error_msg'),
                success: req.flash('success_msg')
            },
            sitekey: recaptchaSiteKey // Pass the site key to your template
        });
    }
});
router.get('/signup', (req, res) => {
    if(req.session.userId){
        res.redirect("/home")
    }
    else {
        res.render('signup', {
            messages: {
                error: req.flash('error_msg'),
                success: req.flash('success_msg')
            },
            sitekey: recaptchaSiteKey // Pass the site key to your template
        });
    }
});
router.post('/login', async (req,res) => {
    const { email, password, 'g-recaptcha-response': recaptchaToken } = req.body;
    const db = req.app.locals.db
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

        // Set userId in session
        req.session.userId = user._id;

        req.flash('success_msg', 'You are now logged in.');
        res.redirect('/home'); // Redirect to dashboard or any other secure route after login

    } catch (err) {
        console.error(err);
        req.flash('error_msg', 'Something went wrong.');
        res.redirect('/login');
    }
});

router.post('/signup', async  (req, res) => {
    console.log()
    const { firstName, lastName, email, birthdate, password, confirmPassword, address, 'g-recaptcha-response': recaptchaToken } = req.body;

    console.log(recaptchaToken)
    const recaptchaVerified = await verifyRecaptcha(recaptchaToken);
    if (!recaptchaVerified) {
        req.flash('error_msg', 'reCAPTCHA verification failed. Please try again.');
        return res.redirect('/login');
    }

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
// Logout route
router.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
            req.flash('error_msg', 'Something went wrong during logout.');
            res.redirect('/home'); // Redirect to home page or login page
        } else {
            res.clearCookie('token'); // Clear JWT token cookie if set
            res.redirect('/login'); // Redirect to login page after logout
        }
    });
});

//Home
router.get('/home', (req, res) => {
    res.render('home');
});
module.exports = router;