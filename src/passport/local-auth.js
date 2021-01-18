const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const flash = require('connect-flash');

const User = require('../models/user');

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async(id, done) => {
    const user = await User.findById(id);
    done(null, user);
});

passport.use("local-signup", new LocalStrategy({
    usernameField: 'username',
    passwordField: 'password',
    passReqToCallback: true
}, async (req, username, password, done) => {

    const newUser = new User();
    newUser.username = username;
    newUser.password = newUser.encryptPassword(password);
    await newUser.save();
    done(null, newUser);

}));

passport.use('local-signin', new LocalStrategy({
    usernameField: 'username',
    passwordField: 'password',
    passReqToCallback: true
}, async(req, username, password, done) => {
    const user = await User.findOne({username: username});
    if (!user) {
        return done(null, false, req.flash('signinmessage','No user found'));
    }
    if (!user.comparePassword(password)){
        return done(null, false, req.flash('signinmessage','Incorrect Password'));
    }
    done(null, user);
}));