require('dotenv').config();
const express = require('express');
const session = require('express-session');
const flash = require('connect-flash');
const rateLimit = require('express-rate-limit');
const path = require('path');
const { MongoClient } = require('mongodb');


const app = express();
const port = 8080;

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(flash());

const rateLimitMiddleware = rateLimit({
    windowMs: 60 * 1000,
    max: 1000,
    message: "Rate Limit Error",
    headers: true,
});
app.use(rateLimitMiddleware);

app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

// Set up view engine and public folder
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

// Routes
const userRoutes = require('./server/routes/userRoutes');
const habiticaRoutes = require('./server/routes/habitica');

app.use('/', userRoutes);
app.use('/', habiticaRoutes);

// MongoDB connection
const client = new MongoClient(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });
client.connect()
    .then(() => {
        console.log('MongoDB connected');
        const db = client.db('habitica-db');
        app.locals.db = db;
    })
    .catch(err => console.error('MongoDB connection error:', err));

// Server
const PORT = 8080;
app.listen(8080, () => console.log(`Server running on port 8080`));
