require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();

// --- MIDDLEWARE ---
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, '../frontend')));

// --- 1. DATABASE CONNECTION ---
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME
}).promise();

db.getConnection()
    .then(connection => {
        console.log("✅ Database Connected Successfully!");
        connection.release();
    })
    .catch(err => console.error("❌ Database Connection Failed:", err.message));

// --- 2. AUTHENTICATION MIDDLEWARE ---
// Use this for any route that needs a valid login token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ message: "Access Denied: No Token Provided" });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: "Invalid or Expired Token" });
        req.user = user; 
        next();
    });
};

// --- 3. PUBLIC ROUTES ---
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/land.html'));
});

// REGISTER
app.post('/auth/register', async (req, res) => {
    try {
        const { fullname, email, password, roleName } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const [roleRows] = await db.query('SELECT id FROM roles WHERE role_name = ?', [roleName]);
        
        if (roleRows.length === 0) return res.status(400).json({ message: "Invalid Role" });

        await db.query('INSERT INTO users (fullname, email, password, role_id) VALUES (?, ?, ?, ?)', 
            [fullname, email, hashedPassword, roleRows[0].id]);

        res.status(201).json({ message: "User created!" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// LOGIN
app.post('/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const [rows] = await db.query(
            `SELECT u.*, r.role_name FROM users u 
             JOIN roles r ON u.role_id = r.id 
             WHERE u.email = ?`, [email]
        );

        if (rows.length === 0) return res.status(401).json({ message: "User not found" });

        const user = rows[0];
        const validPassword = await bcrypt.compare(password, user.password);
        
        if (!validPassword) return res.status(401).json({ message: "Invalid password" });

        const token = jwt.sign(
            { id: user.id, role: user.role_name }, 
            process.env.JWT_SECRET, 
            { expiresIn: '1h' }
        );

        res.json({ token, role: user.role_name, name: user.fullname });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- 4. PROTECTED ROUTES ---
// This is what Postman was looking for!
app.get('/api/dashboard', authenticateToken, (req, res) => {
    res.json({ 
        message: "Welcome to the protected dashboard!", 
        user: req.user 
    });
});

app.get('/auth/profile', authenticateToken, (req, res) => {
    res.json({ user: req.user });
});

// --- 5. START SERVER ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
});