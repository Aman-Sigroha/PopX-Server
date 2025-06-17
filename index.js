require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require("express-rate-limit");
const multer = require('multer');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

// PostgreSQL Connection Pool Configuration using environment variables
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT || 5432,
});

// Test database connection
pool.connect((err, client, release) => {
  if (err) {
    return console.error('Error acquiring client', err.stack);
  }
  client.query('SELECT NOW()', (err, result) => {
    release();
    if (err) {
      return console.error('Error executing query', err.stack);
    }
    console.log('Database connected successfully. Current time:', result.rows[0].now);
  });
});

// Multer Storage Configuration - store in memory
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// Security Middleware
app.use(express.json()); // Body parser
app.use(cors()); // Enable CORS for all routes
app.use(helmet()); // Set various HTTP headers for security
// app.use('/uploads', express.static(path.join(__dirname, 'uploads'))); // REMOVED: No longer serving static files

// Rate limiting to prevent brute-force attacks
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: "Too many requests from this IP, please try again after 15 minutes"
});
app.use(limiter);

// Basic Routes
app.get('/', (req, res) => {
  res.send('Hello from the Express server!');
});

// User Registration Route
app.post('/register', async (req, res, next) => {
  try {
    const { fullname, phonenumber, email, password, companyname, isagency } = req.body;

    // Basic validation
    if (!email || !password || !fullname || !phonenumber) {
      return res.status(400).json({ message: 'Please fill all required fields' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save user to database
    const result = await pool.query(
      'INSERT INTO users (fullname, phonenumber, email, password, companyname, isagency) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *;',
      [fullname, phonenumber, email, hashedPassword, companyname, isagency]
    );

    res.status(201).json({ message: 'User registered successfully', user: result.rows[0] });
  } catch (error) {
    // Handle duplicate email error
    if (error.code === '23505') { // PostgreSQL unique violation error code
      return res.status(409).json({ message: 'Email already registered' });
    }
    next(error); // Pass error to general error handler
  }
});

// User Login Route
app.post('/login', async (req, res, next) => {
  try {
    const { email, password } = req.body;

    // Find user by email
    const result = await pool.query('SELECT * FROM users WHERE email = $1;', [email]);
    const user = result.rows[0];

    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Compare password
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    res.status(200).json({ message: 'Logged in successfully', user: { id: user.id, email: user.email, fullname: user.fullname, profile_image_url: user.profile_image_url, profile_image_mimetype: user.profile_image_mimetype } });
  } catch (error) {
    next(error); // Pass error to general error handler
  }
});

// Profile Picture Upload Route
app.post('/upload-profile-picture', upload.single('profile_picture'), async (req, res, next) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }

    const { userId } = req.body; 

    if (!userId) {
      return res.status(400).json({ message: 'User ID is required' });
    }

    // Store binary data and mimetype directly in the database
    const result = await pool.query(
      'UPDATE users SET profile_image = $1, profile_image_mimetype = $2 WHERE id = $3 RETURNING *;',
      [req.file.buffer, req.file.mimetype, userId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.status(200).json({ message: 'Profile picture uploaded successfully', profile_image_mimetype: req.file.mimetype });
  } catch (error) {
    next(error);
  }
});

// Route to retrieve profile picture
app.get('/profile-picture/:userId', async (req, res, next) => {
  try {
    const { userId } = req.params;
    const result = await pool.query('SELECT profile_image, profile_image_mimetype FROM users WHERE id = $1;', [userId]);
    const user = result.rows[0];

    if (!user || !user.profile_image) {
      return res.status(404).json({ message: 'Profile picture not found' });
    }

    res.set('Content-Type', user.profile_image_mimetype);
    res.send(user.profile_image);
  } catch (error) {
    next(error);
  }
});

// General Error Handling Middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

app.listen(port, () => {
  console.log(`Server listening at http://localhost:${port}`);
});

// Handle graceful shutdown
process.on('SIGINT', () => {
  pool.end(() => {
    console.log('Database connection pool closed.');
    process.exit(0);
  });
}); 