const express = require('express');
const bodyParser = require('body-parser');

const app = express();
const port = 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));

// Routes
app.get('/', (req, res) => {
    res.sendFile('templates/login.html');
});

app.get('/login', (req, res) => {
    res.sendFile(__dirname + '/login.html');
});

app.get('/signup', (req, res) => {
    res.sendFile(__dirname + '/signup.html');
});

app.post('/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    // Check username and password in the database
    // Example: db.collection('users').findOne({ username, password }, (err, user) => { ... });
    // If user is found, authenticate
    res.send(`Logged in as ${username}`);
});

app.post('/signup', (req, res) => {
    const newUsername = req.body.newUsername;
    const newPassword = req.body.newPassword;
    // Save new user to the database
    // Example: db.collection('users').insertOne({ username: newUsername, password: newPassword }, (err, result) => { ... });
    res.send(`Signed up as ${newUsername}`);
});

// Start server
app.listen(port, () => {
    console.log(`Server listening at http://localhost:${port}`);
});
