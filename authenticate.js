var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var JwtStrategy = require('passport-jwt').Strategy;
var User = require('./models/user');
var ExtractJwt = require('passport-jwt').ExtractJwt;
var jwt = require('jsonwebtoken');

var config =  require('./config');

exports.local = passport.use(new LocalStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

exports.getToken = function(user) {
    return jwt.sign(user, config.secretKey, { expiresIn: 3600 });
};

var options = {};

options.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
options.secretOrKey = config.secretKey;

exports.jwtPassport = passport.use(new JwtStrategy(options, (jwt_payload, done) => {
    console.log("JWT payload: ", jwt_payload);

    User.findOne({ _id: jwt_payload._id }, (err, user) => {
        if(err) {
            return done(err, false);
        }
        else if(user) {    // (user !== null)
            return done(null, user);
        }
        else {
            return done(null, false);
        }
    })
}));

exports.verifyUser = passport.authenticate('jwt', { session: false });