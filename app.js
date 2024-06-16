require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const session = require('express-session');
const flash = require('connect-flash');
const path = require('path');
const { MongoClient } = require('mongodb');

const app = express();

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(flash());

// Routes
app.use('/', require('./server/routes/main'));

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
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
