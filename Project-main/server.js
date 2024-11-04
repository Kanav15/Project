const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const argon2 = require('argon2');
const path = require('path');
const ejs = require('ejs');
const multer = require('multer');
const fs = require('fs');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { google } = require('googleapis');
const OAuth2 = google.auth.OAuth2;
require('dotenv').config();
const methodOverride = require('method-override');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(methodOverride('_method'));

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/userAuth', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('Connected to MongoDB successfully'))
.catch((err) => console.error('MongoDB connection error:', err));

// Update User schema to include reset password fields
const userSchema = new mongoose.Schema({
    username: { 
        type: String, 
        required: [true, 'Username is required'],
        unique: true 
    },
    email: { 
        type: String, 
        required: [true, 'Email is required'],
        unique: true,
        trim: true,
        lowercase: true,
        match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email address']
    },
    password: { 
        type: String, 
        required: [true, 'Password is required']
    },
    branch: { 
        type: String, 
        enum: ['cs', 'it', 'aids', 'extc'], 
        required: [true, 'Branch is required'],
        lowercase: true 
    },
    year: { 
        type: Number, 
        enum: [1, 2, 3, 4], 
        required: [true, 'Year is required']
    },
    phone: { 
        type: String, 
        required: [true, 'Phone number is required'],
        validate: {
            validator: function(v) {
                return /^\d{10}$/.test(v);
            },
            message: props => `${props.value} is not a valid 10-digit phone number!`
        }
    },
    role: { 
        type: String, 
        enum: ['student', 'faculty', 'admin'], 
        required: [true, 'Role is required'],
        lowercase: true 
    }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// Notice schema and model
const noticeSchema = new mongoose.Schema({
    title: { type: String, required: true },
    content: { type: String, required: true },
    createdBy: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
});

const Notice = mongoose.model('Notice', noticeSchema);

// File schema and model
const fileSchema = new mongoose.Schema({
    filename: { type: String, required: true },
    originalname: { type: String, required: true },
    path: { type: String, required: true },
    uploadedBy: { type: String, required: true },
    uploadedAt: { type: Date, default: Date.now }
});

const File = mongoose.model('File', fileSchema);

// vLabs Schema and model
const vLabSchema = new mongoose.Schema({
    subject: { type: String, required: true },
    labName: { type: String, required: true },
    labUrl: { type: String, required: true },
    createdBy: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const VLab = mongoose.model('VLab', vLabSchema);
// Middleware setup
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
    secret: process.env.SESSION_SECRET || 'your_fallback_secret',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: process.env.NODE_ENV === 'production' }
}));

// OAuth2 setup for Nodemailer
const createTransporter = async () => {
    const oauth2Client = new OAuth2(
        process.env.GOOGLE_CLIENT_ID,
        process.env.GOOGLE_CLIENT_SECRET,
        "https://developers.google.com/oauthplayground"
    );

    oauth2Client.setCredentials({
        refresh_token: process.env.GOOGLE_REFRESH_TOKEN
    });

    const accessToken = await new Promise((resolve, reject) => {
        oauth2Client.getAccessToken((err, token) => {
            if (err) {
                reject("Failed to create access token :(");
            }
            resolve(token);
        });
    });

    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            type: 'OAuth2',
            user: process.env.EMAIL_USER,
            clientId: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            refreshToken: process.env.GOOGLE_REFRESH_TOKEN,
            accessToken
        }
    });

    return transporter;
};

// Helper function to send email
const sendEmail = async (mailOptions) => {
    try {
        const emailTransporter = await createTransporter();
        await emailTransporter.sendMail(mailOptions);
        console.log("Email sent successfully");
    } catch (error) {
        console.error("Error sending email:", error);
        throw error;
    }
};

// Set EJS as templating engine
app.set('view engine', 'ejs');

// Create uploads directory if it doesn't exist
const uploadDir = 'uploads';
if (!fs.existsSync(uploadDir)){
    fs.mkdirSync(uploadDir);
}

// Configure multer for file upload
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, uploadDir)
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname)
    }
});

const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    }
});

// Request logging middleware
app.use((req, res, next) => {
    console.log('Request Body:', req.body);
    next();
});

// Basic routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/home', (req, res) => {
    if (req.session.user) {
        res.sendFile(path.join(__dirname, 'public', 'home.html'));
    } else {
        res.redirect('/login');
    }
});

// Authentication routes
app.post('/register', async (req, res) => {
    try {
        console.log('Registration request body:', req.body);
        const { username, email, password, branch, year, phone, role } = req.body;

        if (!username || !email || !password || !branch || !year || !phone || !role) {
            return res.status(400).render('error', { 
                message: 'All fields are required' 
            });
        }

        const hashedPassword = await argon2.hash(password);
        const newUser = new User({
            username,
            email,
            password: hashedPassword,
            branch,
            year,
            phone,
            role
        });

        await newUser.save();
        res.redirect('/login');
    } catch (error) {
        console.error('Registration error:', error);
        res.status(400).render('error', { 
            message: 'Registration failed: ' + error.message 
        });
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (user && await argon2.verify(user.password, password)) {
            req.session.user = { username: user.username, role: user.role };
            res.redirect('/home');
        } else {
            res.status(401).render('error', { message: 'Invalid credentials' });
        }
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).render('error', { message: 'Error during login: ' + error.message });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.redirect('/home');
        }
        res.clearCookie('connect.sid');
        res.redirect('/login');
    });
});
// Notice Management Routes

// Get all notices
app.get('/notices', async (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }

    try {
        const notices = await Notice.find().sort({ createdAt: -1 });
        res.render('notices', {
            notices: notices,
            user: req.session.user
        });
    } catch (error) {
        console.error('Error fetching notices:', error);
        res.status(500).render('error', { message: 'Error fetching notices' });
    }
});

// Create new notice
// Notice creation route
app.post('/notices', async (req, res) => {
    if (!req.session.user || (req.session.user.role !== 'faculty' && req.session.user.role !== 'admin')) {
        return res.status(403).json({ error: 'Unauthorized access' });
    }

    try {
        const { title, content } = req.body;
        
        if (!title || !content) {
            return res.status(400).json({ error: 'Title and content are required' });
        }

        const newNotice = new Notice({
            title,
            content,
            createdBy: req.session.user.username,
            createdAt: new Date(),
            updatedAt: new Date()
        });

        await newNotice.save();
        
        // Always send a JSON response
        res.status(201).json({ 
            message: 'Notice created successfully', 
            notice: newNotice 
        });
    } catch (error) {
        console.error('Error creating notice:', error);
        res.status(500).json({ error: 'Error creating notice' });
    }
});

// GET route to display notices
app.get('/notices', async (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }

    try {
        const notices = await Notice.find().sort({ createdAt: -1 });
        res.render('notices', {
            notices: notices,
            user: req.session.user
        });
    } catch (error) {
        console.error('Error fetching notices:', error);
        res.status(500).render('error', { message: 'Error fetching notices' });
    }
});

// Update notice
app.put('/notices/:id', async (req, res) => {
    if (!req.session.user || (req.session.user.role !== 'faculty' && req.session.user.role !== 'admin')) {
        return res.status(403).json({ error: 'Unauthorized access' });
    }

    try {
        const noticeId = req.params.id;
        const { title, content } = req.body;

        if (!title || !content) {
            return res.status(400).json({ error: 'Title and content are required' });
        }

        const updatedNotice = await Notice.findByIdAndUpdate(
            noticeId,
            {
                title,
                content,
                updatedAt: new Date()
            },
            { new: true } // This option returns the updated document
        );

        if (!updatedNotice) {
            return res.status(404).json({ error: 'Notice not found' });
        }

        res.json({
            message: 'Notice updated successfully',
            notice: updatedNotice
        });
    } catch (error) {
        console.error('Error updating notice:', error);
        res.status(500).json({ error: 'Error updating notice' });
    }
}); 

// Delete notice
app.delete('/notices/:id', async (req, res) => {
    if (!req.session.user || (req.session.user.role !== 'faculty' && req.session.user.role !== 'admin')) {
        return res.status(403).json({ error: 'Unauthorized access' });
    }

    try {
        const noticeId = req.params.id;
        const deletedNotice = await Notice.findByIdAndDelete(noticeId);
        
        if (!deletedNotice) {
            return res.status(404).json({ error: 'Notice not found' });
        }
        
        res.json({ message: 'Notice deleted successfully' });
    } catch (error) {
        console.error('Error deleting notice:', error);
        res.status(500).json({ error: 'Error deleting notice' });
    }
});

// Create notice
app.post('/notices', async (req, res) => {
    if (!req.session.user || (req.session.user.role !== 'faculty' && req.session.user.role !== 'admin')) {
        return res.status(403).json({ error: 'Unauthorized access' });
    }

    try {
        const { title, content } = req.body;
        
        if (!title || !content) {
            return res.status(400).json({ error: 'Title and content are required' });
        }

        const newNotice = new Notice({
            title,
            content,
            createdBy: req.session.user.username,
            createdAt: new Date(),
            updatedAt: new Date()
        });

        await newNotice.save();
        
        res.status(201).json({ 
            message: 'Notice created successfully', 
            notice: newNotice 
        });
    } catch (error) {
        console.error('Error creating notice:', error);
        res.status(500).json({ error: 'Error creating notice' });
    }
});

// Search notices
app.get('/notices/search', async (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }

    try {
        const searchQuery = req.query.q;
        const notices = await Notice.find({
            $or: [
                { title: { $regex: searchQuery, $options: 'i' } },
                { content: { $regex: searchQuery, $options: 'i' } }
            ]
        }).sort({ createdAt: -1 });

        res.render('notices', {
            notices: notices,
            user: req.session.user,
            searchQuery: searchQuery
        });
    } catch (error) {
        console.error('Error searching notices:', error);
        res.status(500).render('error', { message: 'Error searching notices' });
    }
});

// File Management Routes
// Upload file
app.post('/upload', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).send('No file uploaded');
        }

        const newFile = new File({
            originalname: req.file.originalname,
            filename: req.file.filename,
            path: req.file.path,
            uploadedBy: req.session.user ? req.session.user.username : 'Unknown'
        });

        await newFile.save();
        res.redirect('/files');
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).send('Error uploading file');
    }
});

// Download file
app.get('/download/:id', async (req, res) => {
    try {
        const file = await File.findById(req.params.id);
        if (!file) {
            return res.status(404).send('File not found');
        }

        // Construct absolute file path
        const filePath = path.join(__dirname, 'uploads', file.filename);
        
        if (!fs.existsSync(filePath)) {
            console.error('File not found at path:', filePath);
            return res.status(404).send('File not found on server');
        }

        res.download(filePath, file.originalname);
    } catch (error) {
        console.error('Download error:', error);
        res.status(500).send('Error downloading file');
    }
});

// Delete file
app.delete('/files/delete/:id', async (req, res) => {
    try {
        const file = await File.findById(req.params.id);
        if (!file) {
            return res.redirect('/files');
        }

        // Construct absolute file path
        const filePath = path.join(__dirname, 'uploads', file.filename);
        
        // Delete file from filesystem if it exists
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
        }

        // Delete file from database
        await File.findByIdAndDelete(req.params.id);

        res.redirect('/files');
    } catch (error) {
        console.error('Delete error:', error);
        res.redirect('/files');
    }
});
//Display files
app.get('/files', async (req, res) => {
    try {
        const files = await File.find().sort({ uploadedAt: -1 });
        res.render('files', { 
            files: files,
            user: req.session.user || null
        });
    } catch (error) {
        console.error('Error fetching files:', error);
        res.status(500).send('Error fetching files');
    }
});

// VLabs routes (add these with other routes)

// VLab routes without AJAX
app.post('/vlabs', upload.single('labFile'), async (req, res) => {
    try {
        // Check if user is authenticated and authorized
        if (!req.session.user || (req.session.user.role !== 'faculty' && req.session.user.role !== 'admin')) {
            return res.status(403).render('error', { message: 'Unauthorized access' });
        }

        const { subject, labName, labUrl } = req.body;

        // Validate required fields
        if (!subject || !labName || !labUrl) {
            return res.render('error', { message: 'All fields are required' });
        }

        // Create new VLab document
        const newVLab = new VLab({
            subject,
            labName,
            labUrl,
            createdBy: req.session.user.username,
            createdAt: new Date(),
            updatedAt: new Date()
        });

        // If a file was uploaded, add file information
        if (req.file) {
            newVLab.fileName = req.file.originalname;
            newVLab.filePath = req.file.path;
        }

        // Save the VLab
        await newVLab.save();

        // Redirect back to vlabs page with success message
        res.redirect('/vlabs?success=VLab created successfully');

    } catch (error) {
        console.error('Error creating VLab:', error);
        res.render('error', { message: 'Error creating VLab: ' + error.message });
    }
});

// Route to display VLabs page
app.get('/vlabs', async (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    try {
        const vlabs = await VLab.find().sort({ createdAt: -1 });
        res.render('vlabs', { user: req.session.user, vlabs: vlabs });
    } catch (error) {
        console.error('Error fetching VLabs:', error);
        res.status(500).render('error', { message: 'Error fetching VLabs' });
    }
});

app.post('/vlabs', async (req, res) => {
    if (!req.session.user || (req.session.user.role !== 'admin' && req.session.user.role !== 'faculty')) {
        return res.status(403).send('Unauthorized');
    }
    try {
        const { subject, labName, labUrl } = req.body;
        const newVLab = new VLab({ subject, labName, labUrl });
        await newVLab.save();
        res.redirect('/vlabs');
    } catch (error) {
        console.error('Error creating VLab:', error);
        res.status(500).send('Error creating VLab');
    }
});

// Delete VLab route
app.delete('/vlabs/:id', async (req, res) => {
    try {
        // Check if user is authenticated and authorized
        if (!req.session.user || (req.session.user.role !== 'admin' && req.session.user.role !== 'faculty')) {
            return res.status(403).json({ success: false, message: 'Unauthorized access' });
        }

        const deletedVLab = await VLab.findByIdAndDelete(req.params.id);
        
        if (!deletedVLab) {
            return res.status(404).json({ success: false, message: 'VLab not found' });
        }

        res.json({ success: true, message: 'VLab deleted successfully' });
    } catch (error) {
        console.error('Error deleting VLab:', error);
        res.status(500).json({ success: false, message: 'Error deleting VLab' });
    }
});
// Search VLabs (modified for AJAX)
app.get('/vlabs/search', async (req, res) => {
    if (!req.session.user) {
        return res.status(403).json({ 
            success: false,
            message: 'Please login first' 
        });
    }

    try {
        const searchQuery = req.query.q;
        const vlabs = await VLab.find({
            $or: [
                { subject: { $regex: searchQuery, $options: 'i' } },
                { labName: { $regex: searchQuery, $options: 'i' } }
            ]
        }).sort({ createdAt: -1 });

        res.json({
            success: true,
            vlabs: vlabs
        });
    } catch (error) {
        console.error('Error searching VLabs:', error);
        res.status(500).json({ 
            success: false,
            message: 'Error searching VLabs: ' + error.message 
        });
    }
});
// NEW PROFILE SECTION
// Profile Routes
app.get('/profile', async (req, res) => {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    try {
        const user = await User.findOne({ username: req.session.user.username })
            .select('-password');
        if (!user) {
            return res.render('error', { message: 'User not found' });
        }
        res.render('profile', { user });
    } catch (error) {
        console.error('Error fetching profile:', error);
        res.render('error', { message: 'Error loading profile' });
    }
});

app.get('/api/user-data', async (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    try {
        const user = await User.findOne({ username: req.session.user.username })
            .select('-password');
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json(user);
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.put('/api/profile', async (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    try {
        const { email, phone, branch, year } = req.body;
        
        // Validation
        const emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }

        const phoneRegex = /^\d{10}$/;
        if (!phoneRegex.test(phone)) {
            return res.status(400).json({ error: 'Invalid phone number format' });
        }

        const validBranches = ['cs', 'it', 'aids', 'extc'];
        if (!validBranches.includes(branch.toLowerCase())) {
            return res.status(400).json({ error: 'Invalid branch' });
        }

        if (![1, 2, 3, 4].includes(Number(year))) {
            return res.status(400).json({ error: 'Invalid year' });
        }

        const updatedUser = await User.findOneAndUpdate(
            { username: req.session.user.username },
            { 
                $set: { 
                    email, 
                    phone, 
                    branch: branch.toLowerCase(), 
                    year: Number(year) 
                } 
            },
            { new: true, runValidators: true }
        ).select('-password');

        if (!updatedUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json(updatedUser);
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ 
            error: 'Server error',
            message: error.message 
        });
    }
});

app.post('/api/change-password', async (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    try {
        const { currentPassword, newPassword } = req.body;

        const user = await User.findOne({ username: req.session.user.username });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const validPassword = await argon2.verify(user.password, currentPassword);
        if (!validPassword) {
            return res.status(400).json({ error: 'Current password is incorrect' });
        }

        if (newPassword.length < 8) {
            return res.status(400).json({ error: 'New password must be at least 8 characters long' });
        }

        const hashedPassword = await argon2.hash(newPassword);
        user.password = hashedPassword;
        await user.save();

        res.json({ message: 'Password updated successfully' });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.delete('/api/profile', async (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    try {
        const user = await User.findOneAndDelete({ username: req.session.user.username });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Clear session
        req.session.destroy(err => {
            if (err) {
                console.error('Session destruction error:', err);
            }
        });

        res.json({ message: 'Account deleted successfully' });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Password Reset Routes
app.post('/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.render('error', { message: 'No account with that email address exists.' });
        }

        const token = crypto.randomBytes(20).toString('hex');
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
        await user.save();

        const mailOptions = {
            to: user.email,
            from: process.env.EMAIL_USER,
            subject: 'Password Reset Request',
            text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n
                Please click on the following link, or paste this into your browser to complete the process:\n\n
                http://${req.headers.host}/reset-password/${token}\n\n
                If you did not request this, please ignore this email and your password will remain unchanged.\n`
        };

        await sendEmail(mailOptions);
        res.render('forgot-password-confirmation');
    } catch (error) {
        console.error('Forgot password error:', error);
        res.render('error', { message: 'Error processing password reset request.' });
    }
});

// Error Handling Middleware
app.use((req, res, next) => {
    res.status(404).render('error', { message: 'Page not found' });
});

app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).render('error', {
        message: 'Something went wrong!',
        error: process.env.NODE_ENV === 'development' ? err : {}
    });
});

// API Health Check
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'healthy',
        timestamp: new Date(),
        uptime: process.uptime()
    });
});

// Security Headers Middleware
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
});

// Rate Limiting
const rateLimit = require('express-rate-limit');

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});

app.use('/api/', limiter);

// Compression
const compression = require('compression');
app.use(compression());

// Start Server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
    console.log('Environment:', process.env.NODE_ENV || 'development');
});

// Graceful Shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM signal received. Closing HTTP server...');
    server.close(() => {
        console.log('HTTP server closed');
        mongoose.connection.close(false, () => {
            console.log('MongoDB connection closed');
            process.exit(0);
        });
    });
});

module.exports = app;