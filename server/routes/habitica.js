const express = require('express');
const router = express.Router();
const isLoggedIn = require('../middleware/isLoggedIn');

// Get routes
router.get('/home', isLoggedIn, (req, res) => {
    res.render('home', { fname: req.session.fname });
});

router.get('/habits', isLoggedIn, (req, res) => {
    res.render('habits', { fname: req.session.fname, messages: req.flash() });
});

// Post routes

router.post('/createhabit', isLoggedIn, async (req, res) => {
    const db = req.app.locals.db;
    const { title, description, frequency } = req.body;

    try {
        if (!title || !frequency) {
            req.flash('error', 'Title and frequency are required.');
            return res.redirect('/habits');
        }
        
        const newHabit = {
            title,
            description: description || '',
            frequency,
            createdBy: req.session.userId,
            createdAt: new Date()
        };

        await db.collection('habits').insertOne(newHabit);

        req.flash('success', 'Habit created successfully!');
        res.redirect('/habits');
    } catch (error) {
        console.error('Error creating habit:', error);
        req.flash('error', 'An error occurred while creating the habit.');
        res.redirect('/habits');
    }
});
module.exports = router;
