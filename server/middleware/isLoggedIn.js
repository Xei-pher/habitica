function isLoggedIn(req, res, next) {
    if (req.session.userId) {
        next();
    } else {
        req.flash('error_msg', 'Please log in to view this page.');
        res.redirect('/login'); // Redirect to login if not logged in
    }
}

module.exports = isLoggedIn;
