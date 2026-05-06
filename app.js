require('dotenv').config(); 
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo').default;
const bcrypt = require('bcrypt');
const saltRounds = 12;
const Joi = require("joi");

const app = express();

const PORT = process.env.PORT || 5000;
const expireTime = 60 * 60 * 1000; // expires after 1 day (minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_user_database = process.env.MONGODB_USER_DATABASE;
const mongodb_session_database = process.env.MONGODB_SESSION_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

const {database} = require('./databaseConnection');
const { emitWarning } = require('node:process');
const userCollection = database.db(mongodb_user_database).collection('users');

app.use(express.static('public'));
app.use(express.urlencoded({extended: false}));
app.use(express.json());

const mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_session_database}`,
    crypto: {
        secret: mongodb_session_secret
    }
});

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: false
}
));

app.get('/', (req, res)=>{
    if(req.session.authenticated)
    {
        res.send(`
            Hello, ${req.session.username}!
            </br>
            <a href="/members">
                <button>Go to Members Area</button>
            </a>
            </br>
            <a href="/logout">
                <button>Logout</button>
            </a>
        `);
    }
    else
    {
        res.send(`
            <a href="/signup">
                <button>Sign Up</button>
            </a>
            </br>
            <a href="/login">
                <button>Log In</button>
            </a>
        `);
    }
});

app.get('/signup', (req, res) => {
    res.send(`
        create user
        <form action='/signupSubmit' method='post'>
        <input name='username' type='text' placeholder='username'></br>
        <input name='email' type='email' placeholder='email'></br>
        <input name='password' type='password' placeholder='password'></br>
        <button>Submit</button>
        </form>
    `)
});

app.post('/signupSubmit', async (req, res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

    if(!username) {
        res.send(`
            User name is required.
            </br>
            </br>
            <a href="/signup">Try again<a>
        `);
    } 
    else if(!email) {
        res.send(`
            Email is required.
            </br>
            </br>
            <a href="/signup">Try again<a>
        `);
    } 
    else if(!password) {
        res.send(`
            Password is required.
            </br>
            </br>
            <a href="/signup">Try again<a>
        `);
    } 
    else {
	    const schema = Joi.object(
            {
                username: Joi.string().required(),
                email: Joi.string().required(),                
                password: Joi.string().required()
            });

        const validationResult = schema.validate({username, email, password});
        
        if(validationResult.error!=null)
        {
            console.log(validationResult.error);
            res.redirect('/signup');
            return;
        }

        var hashedPassword = await bcrypt.hash(password, saltRounds);

        await userCollection.insertOne({username: username, email: email, password: hashedPassword});

        req.session.authenticated = true;
        req.session.username = username;
        req.session.cookie.maxAge = expireTime;

        req.session.save(() => {
            res.redirect('/members');
        });
    }
});

app.get('/login', (req, res) => {
    res.send(`
        log in
        <form action='/loginSubmit' method='post'>
        <input name="email" type="text" placeholder="email">
        <input name="password" type="password" placeholder="password">
        <button>Submit</button>
        </form>
    `)
});

app.post('/loginSubmit', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object(
    {
        email: Joi.string().required(),                
        password: Joi.string().required()
    });

    const validationResult = schema.validate({email, password});
        
    if(validationResult.error!=null)
    {
        console.log(validationResult.error);
        res.redirect('/login');
        return;
    }

	const user = await userCollection.findOne({ email });

    if (!user) {
		res.send(`
            Invalid Email.
            </br>
            </br>
            <a href="/login">Try Again</a>
        `);     
        return;
    }

    if (await bcrypt.compare(password, user.password)) {
        req.session.username = user.username;
        req.session.authenticated = true;
		req.session.cookie.maxAge = expireTime;

		req.session.save(() => {
            res.redirect('/members');
        });
		return;
    }
	else {
		res.send(`
            Incorrect password.
            </br>
            </br>
            <a href="/login">Try Again</a>
        `);
	}
});

app.get('/members', (req, res) => {
    if(!req.session.authenticated) {
        res.redirect('/');
        return;
    }
    res.send(`
        <h1>Hello, ${req.session.username}</h1>
        <a href="/logout">
            <button>Log Out</button>
        </a>
    `)
});

app.get('/logout', (req, res) => {
	req.session.destroy();
    res.redirect('/');
});

app.use((req,res) => {
	res.status(404);
	res.send("Page not found - 404");
});

// Start server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});