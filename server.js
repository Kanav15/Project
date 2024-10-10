const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const multer = require('multer');
const path = require('path');
const bcrypt = require('bcryptjs');
const User = require('./models/user'); // Ensure you have this model defined

const app = express();

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/myapp', { useNewUrlParser: true, useUnifiedTopology: true });

// Middleware setup
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: 'mongodb://localhost:27017/myapp' })
}));

// Configure storage for uploaded files
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

// Initialize Multer with the storage configuration
const upload = multer({ storage });

// Routes

// Signup route
app.get('/signup', (req, res) => {
    res.render('signup');
});

app.post('/signup', async (req, res) => {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = new User({ username: req.body.username, password: hashedPassword, role: req.body.role });
    
    await user.save();
    res.redirect('/login');
});

// Login route
app.get('/login', (req, res) => {
    // Render login page
    res.render('login');
});

app.post('/login', async (req, res) => {
    const user = await User.findOne({ username: req.body.username });
    
    if (user && await bcrypt.compare(req.body.password, user.password)) {
        req.session.userId = user._id;
        req.session.role = user.role;
        
        // Redirect to home page after successful login
        return res.redirect('/home'); 
    }
    
    // Redirect back to login on failure
    res.redirect('/login'); 
});

// Home route
app.get('/home', async (req, res) => {
   if (!req.session.userId) return res.redirect('/login');

   const user = await User.findById(req.session.userId);
   res.render('home', { role: user.role }); // Pass role for conditional rendering
});

// Logout route
app.get('/logout', (req, res) => {
   req.session.destroy();
   res.redirect('/login');
});

// File upload route
app.post('/upload', upload.single('file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }
    
    return res.status(200).json({ 
        message: 'File uploaded successfully!', 
        fileName: req.file.filename 
    });
});

// View files route
app.get('/view', async (req, res) => {
   if (!req.session.userId) return res.redirect('/login');

   fs.readdir('uploads', (err, files) => {
       if (err) return res.status(500).send('Error reading files');
       res.render('viewFiles', { files });
   });
});

// Download route
app.get('/download/:filename', (req, res) => {
   const filePath = path.join(__dirname, 'uploads', req.params.filename);
   res.download(filePath); // This will prompt the user to download the file
});

// Delete route
app.post('/delete/:filename', (req, res) => {
   const filePath = path.join(__dirname, 'uploads', req.params.filename);
   fs.unlink(filePath, (err) => {
       if (err) return res.status(500).send('Error deleting file');
       res.redirect('/view');
   });
});

// Profile route
app.get('/profile', async (req, res) => {
   if (!req.session.userId) return res.redirect('/login');

   const user = await User.findById(req.session.userId);
   res.render('profile', { user });
});

app.post('/profile', async (req, res) => {
   if (!req.session.userId) return res.redirect('/login');

   await User.findByIdAndUpdate(req.session.userId, { username: req.body.username });
   res.redirect('/profile');
});

// Start server
app.listen(3000, () => console.log('Server started on http://localhost:3000'));