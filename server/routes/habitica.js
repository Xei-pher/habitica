const express = require('express');
const router = express.Router();
const isLoggedIn = require('../middleware/isLoggedIn');
const { ObjectId } = require('mongodb');
// Get routes
router.get('/home', isLoggedIn, (req, res) => {
    res.render('home', { fname: req.session.fname });
});

router.get('/habits', isLoggedIn, async (req, res) => {
    try{
        const db = req.app.locals.db;
        const habits = await db.collection('habits').find({ createdBy: req.session.userId }).toArray();

        res.render('habits', { fname: req.session.fname, habits, messages: req.flash() });
    }
    catch(error){
        console.error('Error fetching habits:', error);
        req.flash('error', 'An error occurred while fetching habits.');
        res.redirect('/home');
    }
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

router.post('/deletehabit/:id', async (req, res) => {
    console.log("jacy");
    try {
        const habitId = req.params.id;
        console.log(habitId);
        const db = req.app.locals.db;
        const result = await db.collection('habits').deleteOne({ _id: new ObjectId(habitId) });
        console.log(result);
        if (result) {
            res.json({ success: true });
        } else {
            res.json({ success: false, error: 'Habit not found' });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: 'Server error' });
    }
});
module.exports = router;
