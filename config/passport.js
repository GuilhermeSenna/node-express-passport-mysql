// config/passport.js

// Método para autenticação usuário e login
var LocalStrategy = require('passport-local').Strategy;

// Lib do MySQL
var mysql = require('mysql');

// Hash passwords
var bcrypt = require('bcrypt-nodejs');

// Instância do BD
var dbconfig = require('./database');

// Instância da conexão com o BD
var connection = mysql.createConnection(dbconfig.connection);

// Seleção da tabela
connection.query('USE ' + dbconfig.database);

// expose this function to our app using module.exports
module.exports = (passport) => {

    // =========================================================================
    // passport session setup ==================================================
    // =========================================================================
    // required for persistent login sessions
    // passport needs ability to serialize and unserialize users out of session

    // used to serialize the user for the session
    passport.serializeUser((user, done) => {
        done(null, user.id);
    });

    // used to deserialize the user
    passport.deserializeUser((id, done) => {

        connection.query("SELECT * FROM users WHERE id = ? ", [id], (err, rows) => {
            done(err, rows[0]);
        });

    });

    // =========================================================================
    // LOCAL SIGNUP ============================================================
    // =========================================================================
    // we are using named strategies since we have one for login and one for signup
    // by default, if there was no name, it would just be called 'local'

    passport.use(
        'local-signup',
        new LocalStrategy({
            // by default, local strategy uses username and password, we will override with email
            usernameField: 'username',
            passwordField: 'password',
            passReqToCallback: true // allows us to pass back the entire request to the callback
        },
            (req, username, password, done) => {
                // find a user whose email is the same as the forms email
                // we are checking to see if the user trying to login already exists

                connection.query("SELECT * FROM users WHERE username = ?", [username], (err, rows) => {
                    if (err)
                        return done(err);
                    if (rows.length) {
                        return done(null, false, req.flash('signupMessage', 'That username is already taken.'));
                    } else {

                        // Se não tem um usuário com esse email...
                        // ...Cria um.
                        var newUserMysql = {
                            username: username,
                            password: bcrypt.hashSync(password, null, null)  // use the generateHash function in our user model
                        };

                        var insertQuery = "INSERT INTO users ( username, password ) values (?,?)";

                        connection.query(insertQuery, [newUserMysql.username, newUserMysql.password], (err, rows) => {
                            // Salva o PK do novo usuário adicionado
                            newUserMysql.id = rows.insertId;

                            return done(null, newUserMysql);
                        });

                    }
                });

            })
    );

    // =========================================================================
    // LOCAL LOGIN =============================================================
    // =========================================================================
    // we are using named strategies since we have one for login and one for signup
    // by default, if there was no name, it would just be called 'local'

    passport.use(
        'local-login',
        new LocalStrategy({
            // by default, local strategy uses username and password, we will override with email
            usernameField: 'username',
            passwordField: 'password',
            passReqToCallback: true // allows us to pass back the entire request to the callback
        },
            (req, username, password, done) => { // callback with email and password from our form

                connection.query("SELECT * FROM users WHERE username = ?", [username], function (err, rows) {
                    if (err)
                        return done(err);
                    if (!rows.length) {
                        return done(null, false, req.flash('loginMessage', 'No user found.')); // req.flash is the way to set flashdata using connect-flash
                    }

                    // if the user is found but the password is wrong
                    if (!bcrypt.compareSync(password, rows[0].password))
                        return done(null, false, req.flash('loginMessage', 'Oops! Wrong password.')); // create the loginMessage and save it to session as flashdata

                    // all is well, return successful user
                    return done(null, rows[0]);
                });

            })
    );
};
