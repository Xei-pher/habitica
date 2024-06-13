const express = require('express');
const router = express.Router();

// Routes
router.get('/', (req, res) => {
    res.render('index');
});

router.get('/signup', (req, res) => {
    res.render('signup');
});

module.exports = router;