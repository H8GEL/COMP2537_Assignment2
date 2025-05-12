require("./utils.js");

require('dotenv').config();
const express = require('express');

const session = require('express-session');
const MongoStore = require('connect-mongo');

const bcrypt = require('bcrypt');

const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require('joi');

const expireTime = 1 * 60 * 60 * 1000; // 1 hour

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

app.set('view engine', 'ejs');

app.use(express.static(__dirname + "/public"));

var { database } = require('./databaseConnection.js');

const userCollection = database.db(mongodb_database).collection('users');

//important to parse body text
app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}?retryWrites=true&w=majority`,
    crypto: {
        secret: mongodb_session_secret,
    }

})

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true
}
));

function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req, res, next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.redirect('/login');
    }
}

function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", { error: "Not Authorized" });
        return;
    }
    else {
        next();
    }
}

app.get('/', (req, res) => {
    res.render("index");
});

app.get('/nosql-injection', async (req, res) => {
    var username = req.query.user;

    if (!username) {
        res.send('<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>');
        return;
    }
    console.log("user: " + username);

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(username);

    if (validationResult.error != null) {
        res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
        return;
    }

    const result = await userCollection.findOne({ username: username }).project({ username: 1, password: 1, _id: 1 }).toArray();

    console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/about', (req, res) => {
    var color = req.query.color;

    res.send("<h1 style='color:" + color + "'>Hello World!</h1>");
});

app.get('/signup', (req, res) => {
    res.render("signup")
});

app.post('/submitUser', async (req, res) => {
    const { username, email, password } = req.body;

    // Improved validation schema
    const schema = Joi.object({
        username: Joi.string().pattern(/^[a-zA-Z0-9 ]+$/).max(20).required(),
        email: Joi.string().email().max(30).required(),
        password: Joi.string().min(6).max(20).required()
    });

    const validationResult = schema.validate({ username, email, password });
    if (validationResult.error) {
        return res.render("validationError", { 
            error: validationResult.error.details[0].message 
        });
    }

    // Check for existing user
    const existingUser = await userCollection.findOne({
        $or: [{ username }, { email }]
    });

    if (existingUser) {
        return res.render("signup", { 
            error: "Username or email already exists" 
        });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Insert new user with type
    await userCollection.insertOne({ 
        username, 
        email, 
        password: hashedPassword,
        user_type: 'user'
    });

    // Initialize session properly
    req.session.authenticated = true;
    req.session.username = username;
    req.session.user_type = 'user';
    req.session.cookie.maxAge = expireTime;

    res.redirect('/members');
});

app.get('/login', (req, res) => {
    res.render("login");
});

app.post('/loggingin', async (req, res) => {
    var username = req.body.username;
    var password = req.body.password;

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(username);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.render("login");
        return;
    }

    const result = await userCollection.find({ username: username }).project({ username: 1, password: 1, _id: 1, user_type: 1 }).toArray();

    console.log(result);
    if (result.length != 1) {
        console.log("user not found");
        res.render("loginfail");
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.username = username;
        req.session.user_type = result[0].user_type;
        req.session.cookie.maxAge = expireTime;

        res.render("loggedin", {username: username});
        return;
    }
    else {
        console.log("incorrect password");
        res.render("loginfail");
        return;
    }

});

app.get('/loginfail', (req, res) => {
    res.render("loginfail");

});

app.get('/loggedin', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');

    } else {

        const username = req.session.username;
        res.render("loggedin", { username: username });
    }

});


app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        console.log("user is not authenticated");
        res.render("index");
        return;
    }

    const username = req.session.username;

    res.render("members", { username: username });

});

app.get('/admin', sessionValidation, adminAuthorization, async (req, res) => {
    const users = await userCollection.find().project({ username: 1, _id: 1, user_type: 1 }).toArray();

    res.render("admin", { 
        users: users,
        currentUser: req.session.username
    });
});

app.post('/promote-user', sessionValidation, adminAuthorization, async (req, res) => {
    const username = req.body.username;
    await userCollection.updateOne(
        { username: username },
        { $set: {user_type: 'admin' }}
    );
    res.redirect('/admin')
});

app.post('/demote-user', sessionValidation, adminAuthorization, async (req, res) => {
    const username = req.body.username;
    await userCollection.updateOne(
        { username: username },
        {$set: {user_type: 'user'}}
    );
    res.redirect('/admin');
})


app.get('/logout', (req, res) => {
    req.session.destroy();
    res.render("index");
});

//WHile using express v5, use this 
app.get('*dummy', (req, res) => {
    res.status(404);
    res.render("404");
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`);
});









