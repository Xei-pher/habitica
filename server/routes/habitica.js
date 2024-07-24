const express = require('express');
const router = express.Router();
const isLoggedIn = require('../middleware/isLoggedIn');

// Home
router.get('/home', isLoggedIn, (req, res) => {
    res.render('home', { fname: req.session.fname });
});

router.get('/habits', isLoggedIn, async (req, res) => {
    res.render('habits', { fname: req.session.fname });
  });

module.exports = router;
