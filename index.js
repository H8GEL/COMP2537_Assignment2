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

app.get('/', (req, res) => {
    var html = `
        <form action='/signup'>
            <button>Sign up</button>
        </form>
        <form action='/login'>
            <button>Log in</button>
        </form>`

    res.send(html);
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
    var html = `
    <h1>Create User</h1>
        <form action='/submitUser' method='post'>
            <input name='username' type='text' placeholder='username'></input>
            <br><input name='email' type='text' placeholder='email'></input>
            <br><input name='password' type='password' placeholder='password'></input>
            <br><button>Submit</button>  
        </form>`;
    res.send(html);
});

app.post('/submitUser', async (req, res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object(
        {
            username: Joi.string().alphanum().max(20).required(),
            email: Joi.string().max(30).required(),
            password: Joi.string().max(20).required()
        });

    const validationResult = schema.validate({ username, email, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        var html = `
            <h1>${validationResult.error.details[0].message}</h1>
            <a href='/signup'>Try again</a>`;
        res.send(html);
        return;
    }

    const existingUser = await userCollection.findOne({
        $or: [{ username: username }, { email: email }]
    });

    if (existingUser) {
        var html = `<h1>Username or email already exists. Please try again.</h1>
            <a href='/signup'>Try again</a>`;

        res.send(html);
        return;
    }




    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({ username: username, email: email, password: hashedPassword });
    console.log("Inserted user");
    console.log("successfully created user");


    req.session.authenticated = true;
    req.session.username = username;
    req.session.cookie.maxAge = expireTime;

    res.redirect('/members');
});

app.get('/login', (req, res) => {
    var html = `
        <form action='/loggingin' method='post'>
            <input name='username' type='text' placeholder='username'></input>
            <br><input name='password' type='password' placeholder='password'></input>
            <br><button>Submit</button>
        </form>
        <form action='/signup'>
            <button>Sign Up</button>
        </form>`

    res.send(html);
});

app.post('/loggingin', async (req, res) => {
    var username = req.body.username;
    var password = req.body.password;

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(username);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/login");
        return;
    }

    const result = await userCollection.find({ username: username }).project({ username: 1, password: 1, _id: 1 }).toArray();

    console.log(result);
    if (result.length != 1) {
        console.log("user not found");
        res.redirect("/loginfail");
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.username = username;
        req.session.cookie.maxAge = expireTime;

        res.redirect("/loggedin");
        return;
    }
    else {
        console.log("incorrect password");
        res.redirect("/loginfail");
        return;
    }

});

app.get('/loginfail', (req, res) => {
    res.send('<h1>login/password combination not valid</h1> <a href="/login">Try again</a>');

});

app.get('/loggedin', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');

    } else {

        const username = req.session.username;

        var html = `
            <h1>Hello, ${username}</h1>
            <form action='/members'>
                <button>Go to members area</button>
            </form>
            <form action='/logout'>
                <button>Logout</button>
            </form>`;

        res.send(html);


    }

});

const catimage = () => {
    const num = Math.floor(Math.random() * 3);
    if (num == 1) {
        return '/cat-maxwell.gif';
    } else if (num == 2) {
        return 'giphy.gif';
    } else {
        return 'spore-get-away.gif'
    }
};

app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        console.log("user is not authenticated");
        res.redirect('/');
        return;
    }

    const username = req.session.username;

    const html = `
        <h1>Hello, ${username}</h1>
        <img src="${catimage()}" style="width:250px"></img>
        <form action='/logout'>
            <button>Sign out</button>
        </form>
        `;

    res.send(html);
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

//WHile using express v5, use this 
app.get('*dummy', (req, res) => {
    res.status(404);
    res.send("404 - No page exists!")
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`);
});









