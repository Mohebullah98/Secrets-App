require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const port = 3000;
const mongoose = require("mongoose");
const session =require("express-session");
const passport =require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require( 'passport-google-oauth2' ).Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate =require("mongoose-findorcreate");
const app = express();
app.use(express.urlencoded({
  extended: true
}));
app.set('view engine', 'ejs');
app.use(express.static(__dirname + "/public"));
app.use(session({ //initialize express session
  secret:"our little secret.",
  resave:false,
  saveUninitialized:false
}));
app.use(passport.initialize());
app.use(passport.session());
mongoose.connect("mongodb://localhost:27017/userDB");
//create schema and model for emails and password to store in our db.
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  secret: String,
  googleId:String,
  facebookId:String
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
const User = mongoose.model("User", userSchema);
passport.use(User.createStrategy());
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});
//signing in with google
passport.use(new GoogleStrategy({
    clientID:     process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    passReqToCallback   : true
  },
  function(request, accessToken, refreshToken, profile, done) {
    console.log(profile.id);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return done(err, user);
    });
  }
));
//Signing in with facebook
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    // find or create a user with their facebook id in our server, all we have on the user is their facebook id.
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
app.get("/", function(req, res) {
  res.render("home");
});
//get request that triggers google sign in
app.get('/auth/google',
  passport.authenticate('google', { scope:
      [ 'email', 'profile' ] }
));
//get request that triggers facebook sign in page (button link)
app.get('/auth/facebook',
  passport.authenticate('facebook'));
//get request for callback url after google sign in
app.get( '/auth/google/secrets',
    passport.authenticate( 'google', {
        successRedirect: '/secrets', //if successful redirect to secrets, otherwise back to login
        failureRedirect: '/login'
}));
//get request for callback url after facebook sign in
app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect('/secrets');
  });
app.get("/login", function(req, res) {
  res.render("login");
});
app.get("/register", function(req, res) {
  res.render("register");
});
app.get("/secrets",function(req,res){
  User.find({"secret" :{$ne:null}},function(err,docs){
    if(err) console.log(err);
    else{
      if(docs){
        res.render("secrets",{usersWithSecrets:docs});
      }
    }
  }); //find all secrets stored in DB
});
app.get("/logout",function(req,res){
  req.logout(); //log user out and end session
  res.redirect("/");
});
app.get("/submit",function(req,res){
  if(req.isAuthenticated()){ //user needs to be logged in to submit.
    res.render("submit");
  }
  else{
    res.redirect("/login");
  }
});
app.post("/submit",function(req,res){
  const secretInput = req.body.secret;
  console.log(req.user.id);
  User.findById(req.user.id,function(err,doc){
    if(err) console.log(err);
    else{
      if(doc){
        doc.secret=secretInput;
        doc.save(function(){
          res.redirect("secrets");
        });
      }
    }
  })
})
app.post("/register", function(req, res) { //registering a new user
  User.register({username:req.body.username},req.body.password,function(err,user){
    if(err){
      console.log(err);
      res.redirect("/register");
    }
    else{
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets"); //they should be redirected to secrets if they've successfully registered.
      });
    }
  });
});
app.post("/login", function(req, res) { //when a user logs in
  const user = new User({ //create a User based off input
    username:req.body.username,
    password:req.body.password
  });
  //use passport login function to authenticate user.
  req.login(user,function(err){
    if(err) console.log(err);
    else {passport.authenticate("local")(req,res,function(){
      res.redirect("/secrets");
    });
  }
  });
});
app.listen(port, function(req, res) {
  console.log("Server has started on port 3000");
})
