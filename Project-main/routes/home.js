// routes/home.js
const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect('/auth/login');
    }
    res.render('home', {
        username: req.user.username,
        role: req.user.role,
        branch: req.user.branch,
        year: req.user.year,
        semester: req.user.semester,
    });
});

module.exports = router;
