//jshint esversion:6
require('dotenv').config()
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findorCreate = require('mongoose-findorcreate');
const FacebookStrategy = require('passport-facebook');
const TwitterStrategy = require('passport-twitter');


// const encrypt = require("mongoose-encryption");
// const md5 = require('md5');
// const bcrypt = require('bcrypt');
// const saltRounds = 10;

//basic using
app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(express.static("public"));
app.set('view engine', 'ejs');

app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

//mongodb
mongoose.connect("mongodb://localhost:27017/usersDB");

const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  googleId: String,
  facebookId:String,
  twitterId:String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findorCreate);


// const secret = process.env.secret;
// userSchema.plugin(encrypt, { secret: secret, encryptedFields: ['password']  });

const User = new mongoose.model("User", userSchema);

// use static authenticate method of model in LocalStrategy
passport.use(User.createStrategy());

// use static serialize and deserialize of model for passport session support
passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    cb(null, {
      id: user.id,
      username: user.username
    });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});

///////////////////////////////////////////////google strategy
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    // console.log(profile);
    User.findOrCreate({
      googleId: profile.id
    }, function(err, user) {
      return cb(err, user);
    });
  }
));

///////////////////////////////////////////////facebook strategy
passport.use(new FacebookStrategy({
    clientID: process.env.FB_ID,
    clientSecret: process.env.FB_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    // console.log(profile);
    User.findOrCreate({
      facebookId: profile.id
    }, function(err, user) {
      return cb(err, user);
    });
  }
));
////////////////////////////////////////////////////twitter Strategy
passport.use(new TwitterStrategy({
    consumerKey: process.env.TWITTER_API_KEY,
    consumerSecret: process.env.TWITTER_SECRET,
    callbackURL: "http://localhost:3000/auth/twitter/secrets"
  },
  function(token, tokenSecret, profile, cb) {
    User.findOrCreate({ twitterId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

//routes
app.get("/", function(req, res) {
  res.render("home");
});

//////////////////////////////////////////////////////////////////facebook

app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', {
    failureRedirect: '/login'
  }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

///////////////////////////////////////////////////////////////////google


app.get('/auth/google',
  passport.authenticate('google', {
    scope: ["profile"]
  }));

app.get('/auth/google/secrets',
  passport.authenticate('google', {
    failureRedirect: '/login'
  }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });

///////////////////////////////////////////////////////////////////twitter
app.get('/auth/twitter',
  passport.authenticate('twitter', {
    scope: ["profile"]
  }));

app.get('/auth/twitter/secrets',
  passport.authenticate('twitter', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });


/////////////////////////////////////////////////////////////routes - get
app.get("/login", function(req, res) {
  res.render("login");
});

app.get("/register", function(req, res) {
  res.render("register");
});

app.get("/secrets", function(req, res) {
  if (req.isAuthenticated()) {

User.find({"secret":{$ne:null}},function(err,result){

if(err){
  console.log(err);
}else{
  if(result){
  res.render("secrets",{userSecrets:result});
}
}

});

  } else {
    res.redirect("/login");
  }
});

app.get("/logout", function(req, res) {
  req.logout();
  res.redirect("/");
});

app.get("/submit",function(req,res){
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

///////////////////////////////////////////////////////////////routes - post
app.post("/register", function(req, res) {

  User.register({
    username: req.body.username
  }, req.body.password, function(err, user) {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });

});

app.post("/login", function(req, res) {
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  })

});

app.post("/submit",function(req,res){

const userSecret = req.body.secret;

User.findById(req.user.id,function(err,result){

if(err){
  console.log(err);
}else{
  if(result){
    result.secret = userSecret;
    result.save(function(){
      res.redirect("/secrets")
    });
  }
}

});

});

//basic listining
app.listen("3000", function() {
  console.log("server is running on port 3000");
});
