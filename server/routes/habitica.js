const express = require('express');
const router = express.Router();
const isLoggedIn = require('../middleware/isLoggedIn');

// Home
router.get('/home', isLoggedIn, (req, res) => {
    res.render('home');
});

router.get('/habits', async (req, res) => {
    res.render('habits');
  });

module.exports = router;
