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
    origin: "https://user-management-front-production.up.railway.app",
    methods: "GET,POST,PUT,DELETE",
    credentials: true
}));
app.use(express.json());

// Database connection pool with correct environment variables
const pool = mysql.createPool({
    host: process.env.MYSQLHOST || "mysql-uazh.railway.internal",
    user: process.env.MYSQLUSER || "root",
    password: process.env.MYSQLPASSWORD || "oEkGRfvlzEEkBmlOgBKxcjddgBFNMkQg",
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
        connection.release();
    })
    .catch(err => {
        console.error('Error connecting to the database:', err);
    });

// Authentication middleware
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access denied. No token provided.' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        const [users] = await pool.query('SELECT * FROM users WHERE id = ? AND status = ?',
            [decoded.userId, 'active']);

        if (users.length === 0) {
            return res.status(403).json({ message: 'User is blocked or does not exist' });
        }

        req.user = users[0];
        next();
    } catch (error) {
        res.status(403).json({ message: 'Invalid token' });
    }
};

const isAdmin = (req, res, next) => {
    if (!req.user.isAdmin) {
        return res.status(403).json({ message: 'Access denied. Admin privileges required.' });
    }
    next();
};


app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    try {
        const [existingUsers] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);

        if (existingUsers.length > 0) {
            return res.status(400).json({ message: 'Email already in use' });
        }

        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const [userCount] = await pool.query('SELECT COUNT(*) as count FROM users');
        const isAdmin = userCount[0].count === 0;

        const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
        const [result] = await pool.query(
            'INSERT INTO users (name, email, password, status, registrationTime, lastLogin, isAdmin) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [name, email, hashedPassword, 'active', now, now, isAdmin]
        );

        const [newUser] = await pool.query('SELECT id, name, email, status, isAdmin FROM users WHERE id = ?', [result.insertId]);

        const token = jwt.sign({ userId: newUser[0].id }, JWT_SECRET, { expiresIn: '24h' });

        res.status(201).json({
            message: 'User registered successfully',
            user: newUser[0],
            token
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Error registering user' });
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required' });
    }

    try {
        const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);

        if (users.length === 0) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        const user = users[0];

        if (user.status === 'blocked') {
            return res.status(403).json({ message: 'Your account has been blocked. Please contact an administrator.' });
        }

        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
        await pool.query('UPDATE users SET lastLogin = ? WHERE id = ?', [now, user.id]);

        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '24h' });

        const userWithoutPassword = {
            id: user.id,
            name: user.name,
            email: user.email,
            status: user.status,
            isAdmin: user.isAdmin
        };

        res.json({
            message: 'Login successful',
            user: userWithoutPassword,
            token
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Error during login' });
    }
});

app.get('/users', authenticateToken, isAdmin, async (req, res) => {
    try {
        const [users] = await pool.query(
            'SELECT id, name, email, status, registrationTime, lastLogin, isAdmin FROM users'
        );
        res.json(users);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ message: 'Error fetching users' });
    }
});

app.put('/users/block', authenticateToken, isAdmin, async (req, res) => {
    const { userIds } = req.body;

    if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
        return res.status(400).json({ message: 'User IDs are required' });
    }

    try {
        if (userIds.includes(req.user.id.toString())) {
            return res.status(400).json({ message: 'You cannot block yourself' });
        }

        await pool.query('UPDATE users SET status = ? WHERE id IN (?)', ['blocked', userIds]);
        res.json({ message: 'Users blocked successfully' });
    } catch (error) {
        console.error('Error blocking users:', error);
        res.status(500).json({ message: 'Error blocking users' });
    }
});

app.put('/users/unblock', authenticateToken, isAdmin, async (req, res) => {
    const { userIds } = req.body;

    if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
        return res.status(400).json({ message: 'User IDs are required' });
    }

    try {
        await pool.query('UPDATE users SET status = ? WHERE id IN (?)', ['active', userIds]);
        res.json({ message: 'Users unblocked successfully' });
    } catch (error) {
        console.error('Error unblocking users:', error);
        res.status(500).json({ message: 'Error unblocking users' });
    }
});

app.delete('/users/delete', authenticateToken, isAdmin, async (req, res) => {
    const { userIds } = req.body;

    if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
        return res.status(400).json({ message: 'User IDs are required' });
    }

    try {
        if (userIds.includes(req.user.id.toString())) {
            return res.status(400).json({ message: 'You cannot delete yourself' });
        }

        await pool.query('DELETE FROM users WHERE id IN (?)', [userIds]);
        res.json({ message: 'Users deleted successfully' });
    } catch (error) {
        console.error('Error deleting users:', error);
        res.status(500).json({ message: 'Error deleting users' });
    }
});

app.get('/users/me', authenticateToken, (req, res) => {
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