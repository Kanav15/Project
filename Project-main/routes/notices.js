const express = require('express');
const router = express.Router();
const Notice = require('../models/Notice'); // Import the Notice model

// Middleware to check user role
function checkRole(role) {
    return function(req, res, next) {
        if (req.user.role === role) {
            return res.status(403).send('Access denied.');
        }
        next();
    };
}

// Create a new notice
router.post('/', checkRole('student'), async (req, res) => {
    const { title, content } = req.body;
    const newNotice = new Notice({ title, content, date: new Date() });

    try {
        await newNotice.save();
        res.redirect('/notices'); // Redirect to the notices page after posting
    } catch (error) {
        console.error(error);
        res.status(500).send('Server error');
    }
});

// Update an existing notice
router.post('/:id', checkRole('student'), async (req, res) => {
    const { title, content } = req.body;

    try {
        await Notice.findByIdAndUpdate(req.params.id, { title, content });
        res.redirect('/notices'); // Redirect to the notices page after updating
    } catch (error) {
        console.error(error);
        res.status(500).send('Server error');
    }
});

// Delete a notice
router.delete('/:id', checkRole('student'), async (req, res) => {
    try {
        await Notice.findByIdAndDelete(req.params.id);
        res.redirect('/notices'); // Redirect to the notices page after deleting
    } catch (error) {
        console.error(error);
        res.status(500).send('Server error');
    }
});

// Get all notices
router.get('/', async (req, res) => {
    try {
        const notices = await Notice.find();
        res.render('notices', { notices, user: req.user }); // Render the notices page with notices and user info
    } catch (error) {
        console.error(error);
        res.status(500).send('Server error');
    }
});

module.exports = router;