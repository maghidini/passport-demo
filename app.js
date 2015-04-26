/**
 * Created by maghidini on 4/12/15.
 */
var https = require('https');
var fs = require('fs');
var express = require('express');
var passport = require('passport');
var FacebookStrategy = require('passport-facebook').Strategy;
var passportLocal = require('passport-local');
var passportHttp = require('passport-http');
var bodyParser = require('body-parser');
var cookieParser = require('cookie-parser');
var expressSession = require('express-session');

var app = express();

var server = https.createServer({
    cert: fs.readFileSync(__dirname + '/my.crt'),
    key: fs.readFileSync(__dirname + '/my.key')
}, app);

app.set('view engine','ejs');

app.use(bodyParser.urlencoded({extended:false}));
app.use(cookieParser());
app.use(expressSession(
    {
        secret: process.env.SESSION_SECRET || 'secret',
        saveUninitialized:false,
        resave:false
    }));

app.use(passport.initialize());
app.use(passport.session());

function verifyCredentials(username, password, done) {
    if(username === password ){
        done(null, {id: username, name: username});
    }else{
        done(null, null);
    }
}

passport.use(new passportLocal.Strategy(verifyCredentials));

passport.use(new passportHttp.BasicStrategy(verifyCredentials));

passport.use(new FacebookStrategy({
        clientID: 'FacebookAppIdHere', //Change this
        clientSecret: 'FacebookAppSecretHere', //Change this
        callbackURL: "https://127.0.0.1:1337/auth/facebook/callback" //Should be registered as Valid OAuth redirect URIs
                                                                     //on yours Facebook App Advanced Setting
    },
    function(accessToken, refreshToken, profile, done) {
        done(null, profile)
    }
));

passport.serializeUser(function (user, done) {
    done(null,user.id);
});

passport.deserializeUser(function (id, done) {
    //Query to database or cache here!
    done(null, {id: id, name: id});
});

app.get('/auth/facebook', passport.authenticate('facebook'));

app.get('/auth/facebook/callback',
    passport.authenticate('facebook', { successRedirect: '/',
        failureRedirect: '/login' }));

app.get('/', function (req, res) {
    res.render('index',{
        isAuthenticated: req.isAuthenticated(),
        user: req.user
    })
});

app.get('/login', function (req, res) {
    res.render('login')
});

//passport.authenticate('local') returns a function that will be called by Express as a middleware
app.post('/login', passport.authenticate('local'), function (req, res) {
    res.redirect('/');
});

app.get('/logout', function (req, res) {
    req.logout();
    res.redirect('/');
});

function ensureAuthenticated(req,res,next){
    if (req.isAuthenticated()){
        next();
    }else{
        res.sendStatus(403);
    }
}

app.use('/api', passport.authenticate('basic',{session:false}));


app.get('/api/data',ensureAuthenticated, function (req, res) {
    res.json([
        {value: 'foo'},
        {value: 'bar'},
        {value: 'baz'}
    ])
});

var port = process.env.PORT || 1337;

server.listen(port, function () {
    console.log('https://127.0.0.1:' + port + '/');
});

// openssl req -x509 -nodes -days 365 -newkey rsa:1024 -out my.crt -keyout my.key
