const express = require('express');
const router = express.Router();
const isLoggedIn = require('../middleware/isLoggedIn');
const { ObjectId } = require('mongodb');

// Get routes
router.get('/home', isLoggedIn, async (req, res) => {
    db = req.app.locals.db;
    try{
        const habits = await db.collection('habits').find({createdBy: req.session.userId}).toArray();
        res.render('home', { fname: req.session.fname, habits: Array.isArray(habits) ? habits : [], createdBy: req.session.userId });
    }
    catch(error){
        console.error('Error fetching habits:', error);
        res.status(500).send('Internal Server Error');
    }
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

router.get('/gethabit/:id', isLoggedIn, async (req, res) => {
    try {
        const habitId = req.params.id;
        const db = req.app.locals.db;
        const habit = await db.collection('habits').findOne({ _id: new ObjectId(habitId) });

        if (habit) {
            res.json({ success: true, data: habit });
        } else {
            res.json({ success: false, error: 'Habit not found' });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: 'Server error' });
    }
});


router.get('/about', isLoggedIn, (req, res) => {
    res.render('about', { fname: req.session.fname, messages: req.flash() });
});

router.get('/habitLogs/:habitId', isLoggedIn, async (req, res) => {
    try {
        const habitId = req.params.habitId;
        const createdBy = req.session.userId;
        const db = req.app.locals.db;

        const today = new Date();
        today.setHours(0, 0, 0, 0); // Start of the day

        const log = await db.collection('habitLogs').findOne({
            userId: createdBy,
            habitId: new ObjectId(habitId),
            date: today
        });

        res.json(log || { completed: false });
    } catch (error) {
        console.error('Error fetching habit log:', error);
        res.status(500).send('Internal Server Error');
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

router.post('/deletehabit/:id', isLoggedIn, async (req, res) => {
    try {
        const habitId = req.params.id;
        const db = req.app.locals.db;
        const result = await db.collection('habits').deleteOne({ _id: new ObjectId(habitId) });
        if (result) {
            res.json({ success: true });
        } else {
            res.json({ success: false, error: 'Habit not found' });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: 'Server error' });
    }
});

router.post('/updatehabit', async (req, res) => {
    try {
        const { id, title, description, frequency } = req.body;
        const db = req.app.locals.db;
        const result = await db.collection('habits').updateOne(
            { _id: new ObjectId(id) },
            { $set: { title, description, frequency } }
        );

        if (result.matchedCount > 0) {
            req.flash('success', 'Successfully updated habit.');
            res.redirect('/habits');
        } else {
            
            res.json({ success: false, error: 'Habit not found' });
        }
    } catch (error) {
        res.status(500).send({ success: false, error: 'Failed to update habit' });
    }
});

router.post('/updateHabitLog', isLoggedIn, async (req, res) => {
    const { habitId, completed, description } = req.body;
    const createdBy = req.session.userId;
    const db = req.app.locals.db;

    try {
        const habit = await db.collection('habits').findOne({ _id: new ObjectId(habitId) });

        if (!habit) {
            return res.status(404).send('Habit not found');
        }

        const today = new Date();
        const resetDate = habit.frequency === 'daily' ? today.setHours(0, 0, 0, 0) : today.setDate(today.getDate() - today.getDay());

        // Update the habit log based on the frequency
        await db.collection('habitLogs').updateOne(
            { userId: createdBy, habitId: new ObjectId(habitId), date: new Date(resetDate) },
            {
                $set: {
                    completed: completed,
                    description: description
                }
            },
            { upsert: true }
        );

        res.status(200).send('Habit log updated successfully');
    } catch (error) {
        console.error('Error updating habit log:', error);
        res.status(500).send('Internal Server Error');
    }
});


module.exports = router;
