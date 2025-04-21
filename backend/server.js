const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const PORT = 5000;

// In-memory users for demo (replace with DB in production)
const users = [{ username: 'user@example.com', password: 'pass' }];

app.use(cors());
app.use(bodyParser.json());

// Test route
app.get('/', (req, res) => {
    res.send('Backend is running!');
});

// Signup route
app.post('/api/signup', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password || !username.includes('@')) {
        return res.status(400).json({ success: false, message: 'Invalid email or password.' });
    }
    if (users.find(u => u.username === username)) {
        return res.status(409).json({ success: false, message: 'User already exists.' });
    }
    users.push({ username, password });
    res.json({ success: true, username });
});

// Login route
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username && u.password === password);
    if (user) {
        res.json({ success: true, username });
    } else {
        res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});