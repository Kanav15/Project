// routes/auth.js
const express = require('express');
const passport = require('../config/passport');
const User = require('../models/User');
const router = express.Router();

// Render the login page
router.get('/login', (req, res) => {
    res.render('login', { messages: req.flash('error') });
});

// Handle login form submission
router.post('/login', passport.authenticate('local', { 
    successRedirect: '/home', 
    failureRedirect: '/auth/login',
    failureFlash: true 
}));

// Logout route
router.get('/logout', (req, res) => {
    req.logout();
    res.redirect('/auth/login');
});

// Render the registration page
router.get('/register', (req, res) => {
    res.render('register', { messages: req.flash('error') });
});

// Handle registration form submission
router.post('/register', async (req, res) => {
    const { username, password, role, branch, year, semester } = req.body;

    try {
        const newUser = new User({ username, password, role, branch, year, semester });
        await newUser.save();
        req.flash('success', 'Registration successful! You can now log in.');
        res.redirect('/auth/login');
    } catch (error) {
        req.flash('error', 'Registration failed. ' + error.message);
        res.redirect('/auth/register');
    }
});

module.exports = router;
