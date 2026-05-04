require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const app = express();
const Joi = require("joi"); // Add this at the top with your other requires
let PORT = 3000;
const expireTime = 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_database = process.env.MONGODB_SESSION_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

const { database } = require("./databaseConnection");
const userCollection = database.db(mongodb_database).collection("users");

app.use(express.urlencoded({ extended: false }));

let mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_session_database}`,
    crypto: {
        secret: mongodb_session_secret
    }
});

app.use(
  session({
    secret: node_session_secret,
    resave: false,
    store: mongoStore,
    saveUninitialized: true,
  }),
);

app.get("/", (req, res) => {
  if (!req.session.authenticated) {
    let html = `<a href='/signup'><button>Sign up</button></a><br>
        <a href='/login'><button>Log in</button></a>`;
    res.send(html);
  } else {
    let html = `Hello, ${req.session.username}!<br>
        <a href='/members'><button>Go to Members Area</button></a><br>
        <a href='/logout'><button>Logout</button></a>`;
    res.send(html);
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});



// Signup Page
app.get('/signup', (req, res) => {
    res.send(`
        <form action='/signupSubmit' method='post'>
            <input name='username' type='text' placeholder='username'><br>
            <input name='email' type='email' placeholder='email'><br>
            <input name='password' type='password' placeholder='password'><br>
            <button>Submit</button>
        </form>
    `);
});

// Signup Logic
app.post('/signupSubmit', async (req, res) => {
    let {username, email, password} = req.body;
    
    // Joi Validation (Required)
    const schema = Joi.object({
        username: Joi.string().alphanum().max(20).required(),
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({username, email, password});
    if (validationResult.error) {
        res.send(`${validationResult.error.details[0].message}. <a href='/signup'>Try again.</a>`);
        return;
    }

    const hashedPassword = await bcrypt.hash(password, 10); // Hash password
    await userCollection.insertOne({username, email, password: hashedPassword});
    
    req.session.authenticated = true;
    req.session.username = username;
    res.redirect('/members');
});

app.get('/login', (req, res) => {
    res.send(`
        <h2>Log In</h2>
        <form action='/loggingin' method='post'>
            <input name='email' type='email' placeholder='email'><br>
            <input name='password' type='password' placeholder='password'><br>
            <button>Submit</button>
        </form>
    `);
});

app.post('/loggingin', async (req, res) => {
    let { email, password } = req.body;

    // Search for user by email
    const user = await userCollection.findOne({ email: email });

    // Compare hashed password
    if (user && await bcrypt.compare(password, user.password)) {
        req.session.authenticated = true;
        req.session.username = user.username;
        req.session.cookie.maxAge = expireTime; // Use your 1-hour expireTime
        res.redirect('/members');
    } else {
        res.send("Invalid email/password combination. <a href='/login'>Try again</a>");
    }
});


app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/'); // Protect the route
        return;
    }

    const images = ['pic1.jpg', 'pic2.jpg', 'pic3.jpg']; // Ensure these exist in your /public folder
    const randomImage = images[Math.floor(Math.random() * images.length)];

    res.send(`
        <h1>Hello, ${req.session.username}!</h1>
        <img src='/${randomImage}' style='width:300px;'><br>
        <a href='/logout'><button>Logout</button></a>
    `);
});

app.use(express.static(__dirname + "/public"));

app.use((req,res) => {
	res.status(404);
	res.send("Page not found - 404");
});

app.listen(PORT, () => {
  console.log("Node application listening on port" + PORT);
});
