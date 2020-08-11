const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const sessions = require("client-sessions");    // manages session cookies
const bcrypt = require("bcryptjs");             // hash utility for passwords
const csurf = require("csurf");                 // manage request form fraud (csrf)
const helmet = require("helmet");               // manage http header security

const keys = require("./keys");

let User = mongoose.model("User", new mongoose.Schema({
    firstName:  {type: String, required: true},
    lastName:   {type: String, required: true},
    email:      {type: String, required: true, unique: true},
    password:   {type: String, required: true}
}));

mongoose.connect("mongodb://localhost/ss-auth");

let app = express();

// middleware ----------------------------------

app.set("view engine", "pug");

app.use(bodyParser.urlencoded({
    extended:false
}));

app.use(sessions({
    cookieName: keys.SESSION_COOKIE,
    secret: keys.COOKIE_SECRET,
    duration: 30 * 60 * 1000,
    activeDuration: 5 * 60 * 1000,
    httpOnly: true,     // don't let JS code access cookies
    secure: true,       // only set cookies over https
    ephemeral: true     // destroy cookies when the browser closes
}));

app.use(csurf());
app.use(helmet());

app.use((req, res, next) => {
    if (!(req.session && req.session.userId)) {
        return next();
    }

    User.findById(req.session.userId, (err, user) => {
        if (err) return next(err);

        if (!user) return next();

        user.password = undefined; 

        req.user = user;
        res.locals.user = user;

        next();
    });
});

// Functions -----------------------------------

function loginRequired(req, res, next) {
    if (!req.user) {
        return res.redirect("./login");
    }

    next();
}

// Routes --------------------------------------

app.get("/", (req, res) => {
    res.render("index");
});

app.get("/register", (req, res) => {
    res.render("register", { csrfToken: req.csrfToken() });
});

app.get("/login", (req, res) => {
    res.render("login", { csrfToken: req.csrfToken() });
});

app.get("/dashboard", loginRequired, (req, res, next) => {
    if (!(req.session && req.session.userId)) {
        return res.redirect("/login");
    }

    User.findById(req.session.userId, (err, user) => {
        if (err) return next(err);

        if (!user) return res.redirect("/login");
        
        res.render("dashboard");
    })
});

app.post("/register", (req, res) => {
    
    let  hash = bcrypt.hashSync(req.body.password, 14);
    req.body.password = hash;

    let user = new User(req.body);

    user.save((err) => {
        if (err) {
            let error = "Something bad happened! Please try again.";

            if (err.code === 11000) {
                error = "That email is already taken, please try another";
            }

            return res.render("register", { error: error });
        }
        
        res.redirect("/dashboard");
    });
});

app.post("/login", (req, res) => {
    User.findOne({ email: req.body.email }, (err, user) => {

        if (!user || !bcrypt.compareSync(req.body.password, user.password)) {
            return res.render ("login", {
                error: "Incorrect email/password."
            });
        }

        req.session.userId = user._id;
        res.redirect("/dashboard");
    });
});

app.listen(3000);