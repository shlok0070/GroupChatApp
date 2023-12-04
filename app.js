require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');  // Import the jsonwebtoken library
const { Sequelize, DataTypes } = require('sequelize');

const app = express();
const port = 3000;

app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));

// Replace with your MySQL connection details
const sequelize = new Sequelize(process.env.DB_NAME, process.env.DB_USER, process.env.DB_PASSWORD, {
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    dialect: 'mysql',
});

// Define User model
const User = sequelize.define('User', {
    name: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    email: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
    },
    phone: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    password: {
        type: DataTypes.STRING,
        allowNull: false,
    },
});

// Synchronize the model with the database
sequelize.sync().then(() => {
    console.log('Database and table synced');
}).catch((err) => {
    console.error('Error syncing database:', err);
});

// Authentication Middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// Existing Routes

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/views/login.html');
});

app.get('/login', (req, res) => {
    res.sendFile(__dirname + '/views/login.html');
});

app.get('/signup', (req, res) => {
    res.sendFile(__dirname + '/views/signup.html');
});

// Signup route
app.post('/signup', async (req, res) => {
    const { name, email, phone, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ where: { email } });

    if (existingUser) {
        return res.status(400).json({ message: 'User already exists' });
    }

    // Encrypt the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user in the database
    try {
        await User.create({ name, email, phone, password: hashedPassword });
        console.log('User created in the database');
        res.json({ message: 'Signup successful' });
    } catch (error) {
        console.error('Error creating user:', error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

// Login route
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    // Check if user exists
    const existingUser = await User.findOne({ where: { email } });

    if (!existingUser) {
        return res.status(404).json({ message: 'User not found, please register using the Sign Up option below.' });
    }

    // Check password
    const passwordMatch = await bcrypt.compare(password, existingUser.password);

    if (!passwordMatch) {
        return res.status(401).json({ message: 'Incorrect Password.' });
    }

    // If password is correct, create a JWT
    const token = jwt.sign({ userId: existingUser.id }, process.env.JWT_SECRET, { expiresIn: '1h' });

    // Send the JWT to the frontend
    res.json({ message: 'Login successful', token });
});

// Dashboard route
app.get('/dashboard', (req, res) => {
    res.sendFile(__dirname + '/views/dashboard.html');
});

// Dashboard API route
app.get('/dashboard-data', authenticateToken, (req, res) => {
    // Here you would gather the data needed for the dashboard and send it as JSON
    // For example, you could send the user's name, email, etc.
    // For now, let's just send a success message
    res.json({ message: 'You are authenticated', user: req.user });
});

// Setting up the server with socket.io
const server = require('http').Server(app);
const io = require('socket.io')(server);

// Authenticate WebSocket connections with JWT
io.use((socket, next) => {
    const token = socket.handshake.query.token;
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return next(new Error('Authentication error'));
        }
        socket.decoded = decoded; // If needed, you can access the decoded data in your connection handler
        next();
    });
});

// Users connected to the chat
const onlineUsers = new Map();

io.on('connection', (socket) => {
    console.log('a user connected');
    const decoded = socket.decoded;
    if (decoded && decoded.userId) {
        User.findByPk(decoded.userId).then(user => {
            if (user) {
                onlineUsers.set(socket.id, user.name);
                io.emit('user list', Array.from(onlineUsers.values()));
                socket.on('chat message', (msg) => {
                    io.emit('chat message', { user: user.name, text: msg });
                });
            }
        });
    }

    socket.on('disconnect', () => {
        onlineUsers.delete(socket.id);
        io.emit('user list', Array.from(onlineUsers.values()));
        console.log('user disconnected');
    });
});


server.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
