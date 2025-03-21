const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

app.use(cors({
    origin: "*",
    methods: "GET,POST,PUT,DELETE",
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

const pool = mysql.createPool({
    host: process.env.MYSQLHOST || "mysql-fzhf.railway.internal",
    user: process.env.MYSQLUSER || "root",
    password: process.env.MYSQLPASSWORD || "aNtfzjmjtlkjdjajmnhzawBrEDdokjJt",
    database: process.env.MYSQLDATABASE || "railway",
    port: process.env.MYSQLPORT || 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Test database connection
pool.getConnection()
    .then(connection => {
        console.log('Database connected successfully');
        console.log('Connection config:', {
            host: connection.config.host,
            database: connection.config.database,
            port: connection.config.port
        });
        connection.release();
    })
    .catch(err => {
        console.error('Error connecting to the database:', err);
    });

// Authentication middleware with enhanced logging
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    console.log('Auth attempt, token present:', !!token);

    if (!token) {
        return res.status(401).json({ message: 'Access denied. No token provided.' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        console.log('Token verified, user ID:', decoded.userId);

        const [users] = await pool.query('SELECT * FROM users WHERE id = ? AND status = ?',
            [decoded.userId, 'active']);
        console.log('User found:', users.length > 0);

        if (users.length === 0) {
            return res.status(403).json({ message: 'User is blocked or does not exist' });
        }

        req.user = users[0];
        next();
    } catch (error) {
        console.error('Token verification error:', error);
        res.status(403).json({ message: 'Invalid token' });
    }
};

const isAdmin = (req, res, next) => {
    console.log('Admin check, isAdmin:', req.user.isAdmin);
    if (!req.user.isAdmin) {
        return res.status(403).json({ message: 'Access denied. Admin privileges required.' });
    }
    next();
};

app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;
    console.log('Registration attempt:', email);

    if (!name || !email || !password) {
        console.log('Registration missing fields:', { name: !!name, email: !!email, password: !!password });
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        const [existingUsers] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
        console.log('Existing user check:', existingUsers.length > 0 ? 'Email already exists' : 'Email available');

        if (existingUsers.length > 0) {
            return res.status(400).json({ message: 'Email already in use' });
        }

        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        console.log('Password hashed successfully');

        const [userCount] = await pool.query('SELECT COUNT(*) as count FROM users');
        const isAdmin = userCount[0].count === 0;
        console.log('User count:', userCount[0].count, 'isAdmin:', isAdmin);

        const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
        const [result] = await pool.query(
            'INSERT INTO users (name, email, password, status, registrationTime, lastLogin, isAdmin) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [name, email, hashedPassword, 'active', now, now, isAdmin]
        );
        console.log('User inserted, ID:', result.insertId);

        const [newUser] = await pool.query('SELECT id, name, email, status, isAdmin FROM users WHERE id = ?', [result.insertId]);
        console.log('New user retrieved:', newUser.length > 0);

        const token = jwt.sign({ userId: newUser[0].id }, JWT_SECRET, { expiresIn: '24h' });
        console.log('Generated Token:', token);

        res.status(201).json({
            message: 'User registered successfully',
            user: newUser[0],
            token
        });
    } catch (error) {
        console.error('Registration error details:', error);
        res.status(500).json({ message: 'Error registering user', error: error.message });
    }
});

app.post('/login', async (req, res) => {
    console.log('Login request received, body:', req.body);
    const { email, password } = req.body;

    if (!email || !password) {
        console.log('Missing email or password');
        return res.status(400).json({ message: 'Email and password are required' });
    }

    try {
        console.log('Querying user with email:', email);
        const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
        console.log('User query results:', users.length > 0 ? 'User found' : 'User not found');
        

        if (users.length === 0) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        const user = users[0];
        console.log('User status:', user.status);

        if (user.status === 'blocked') {
            console.log('User is blocked:', email);
            return res.status(403).json({ message: 'Your account has been blocked. Please contact an administrator.' });
        }

        console.log('Stored password hash (first 10 chars):', user.password.substring(0, 10) + '...');

        console.log('Comparing passwords...');
        const validPassword = await bcrypt.compare(password, user.password);
        console.log('Password validation result:', validPassword ? 'Valid' : 'Invalid');

        if (!validPassword) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
        await pool.query('UPDATE users SET lastLogin = ? WHERE id = ?', [now, user.id]);
        console.log('Last login updated for user ID:', user.id);

        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '24h' });
        console.log('Generated Token:', token);

        const userWithoutPassword = {
            id: user.id,
            name: user.name,
            email: user.email,
            status: user.status,
            isAdmin: user.isAdmin
        };

        console.log('Login successful for:', email);
        res.json({
            message: 'Login successful',
            user: userWithoutPassword,
            token
        });
    } catch (error) {
        console.error('Login error details:', error);
        res.status(500).json({ message: 'Error during login', error: error.message });
    }
});

app.get('/users', authenticateToken, isAdmin, async (req, res) => {
    console.log('Get all users request');
    try {
        const [users] = await pool.query(
            'SELECT id, name, email, status, registrationTime, lastLogin, isAdmin FROM users'
        );
        console.log('Users fetched, count:', users.length);
        res.json(users);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ message: 'Error fetching users', error: error.message });
    }
});

app.put('/users/block', authenticateToken, isAdmin, async (req, res) => {
    const { userIds } = req.body;
    console.log('Block users request, IDs:', userIds);

    if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
        console.log('Invalid user IDs for blocking');
        return res.status(400).json({ message: 'User IDs are required' });
    }

    try {
        if (userIds.includes(req.user.id.toString())) {
            console.log('Attempt to block self rejected');
            return res.status(400).json({ message: 'You cannot block yourself' });
        }

        await pool.query('UPDATE users SET status = ? WHERE id IN (?)', ['blocked', userIds]);
        console.log('Users blocked successfully, count:', userIds.length);
        res.json({ message: 'Users blocked successfully' });
    } catch (error) {
        console.error('Error blocking users:', error);
        res.status(500).json({ message: 'Error blocking users', error: error.message });
    }
});

app.put('/users/unblock', authenticateToken, isAdmin, async (req, res) => {
    const { userIds } = req.body;
    console.log('Unblock users request, IDs:', userIds);

    if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
        console.log('Invalid user IDs for unblocking');
        return res.status(400).json({ message: 'User IDs are required' });
    }

    try {
        await pool.query('UPDATE users SET status = ? WHERE id IN (?)', ['active', userIds]);
        console.log('Users unblocked successfully, count:', userIds.length);
        res.json({ message: 'Users unblocked successfully' });
    } catch (error) {
        console.error('Error unblocking users:', error);
        res.status(500).json({ message: 'Error unblocking users', error: error.message });
    }
});

app.delete('/users/delete', authenticateToken, isAdmin, async (req, res) => {
    const { userIds } = req.body;
    console.log('Delete users request, IDs:', userIds);

    if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
        console.log('Invalid user IDs for deletion');
        return res.status(400).json({ message: 'User IDs are required' });
    }

    try {
        if (userIds.includes(req.user.id.toString())) {
            console.log('Attempt to delete self rejected');
            return res.status(400).json({ message: 'You cannot delete yourself' });
        }

        await pool.query('DELETE FROM users WHERE id IN (?)', [userIds]);
        console.log('Users deleted successfully, count:', userIds.length);
        res.json({ message: 'Users deleted successfully' });
    } catch (error) {
        console.error('Error deleting users:', error);
        res.status(500).json({ message: 'Error deleting users', error: error.message });
    }
});

app.get('/users/me', authenticateToken, (req, res) => {
    console.log('Get current user profile, ID:', req.user.id);
    const userWithoutPassword = {
        id: req.user.id,
        name: req.user.name,
        email: req.user.email,
        status: req.user.status,
        isAdmin: req.user.isAdmin
    };

    res.json(userWithoutPassword);
});

app.get("/", (req, res) => {
    console.log('Health check request received');
    res.send("User Management Backend is running!");
});

// Start server with proper error handling
const server = app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

// Handle graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received, shutting down gracefully');
    server.close(() => {
        console.log('Server closed');
        pool.end().then(() => {
            console.log('Database pool closed');
            process.exit(0);
        });
    });
});