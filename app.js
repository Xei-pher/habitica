require('dotenv').config();

const express = require('express');
const expressLayout = require('express-ejs-layouts');
const bodyParser = require('body-parser');

const app = express();
const port = 3000 || process.env.port;

app.use(express.static('public'));
// Middleware
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

// Routes
app.use('/', require('./server/routes/main'));

// Start server
app.listen(port, () => {
    console.log(`Server listening at http://localhost:${port}`);
});
