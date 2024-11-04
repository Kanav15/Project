const express = require('express');
const router = express.Router();

// Profile route
router.get('/', (req, res) => {
  if (!req.session || !req.session.user) {
    return res.redirect('/auth/login'); // Redirect to login if not authenticated
  }

  const { username, role, branch, year, phone } = req.session.user;
  res.render('profile', { username, role, branch, year, phone });
});

module.exports = router;
