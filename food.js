import express from 'express';
import bodyParser from 'body-parser';
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import passport from 'passport';
import { Strategy } from 'passport-local';
import GoogleStrategy from 'passport-google-oauth20';
import session from 'express-session';
import NodeCache from 'node-cache';
import dotenv from 'dotenv';

const cache = new NodeCache();

const FoodSchema = new mongoose.Schema({
    id: String,
    FoodTitle: String,
    FoodContent: String,
    authorId: String,
    subscribedUserId: String,
    activeSubscriber: Boolean 
});

const userSchema = new mongoose.Schema({
    _id: mongoose.Schema.Types.ObjectId,
    email: String,
    password: String,
    googleId: String,
    role: { type: String, enum: ['user', 'specialUser'], default: 'user' }
});

const Food = mongoose.model('Food', FoodSchema);
const User = mongoose.model('User', userSchema);

const app = express();

dotenv.config();

mongoose.connect('mongodb+srv://suhas:suhas2244@cluster0.nhaclgq.mongodb.net/');

const db = mongoose.connection;

db.on('error', console.error.bind(console, 'MongoDB connection error'));

db.once('open', () => {
    console.log('MongoDB connected');
});

app.use(
    session({
        secret: 'asdddfafasd',
        resave: false,
        saveUninitialized: true 
    })
);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(passport.initialize());
app.use(passport.session());

app.get('/', (req, res) => {
    res.render('home.ejs');
});

app.get('/login', (req, res) => {
    res.render('login.ejs');
});

app.get('/register', (req, res) => {
    res.render('register.ejs');
});

app.get('/logout', (req, res) => {
    req.logout(function (err) {
        if (err) {
            return next(err);
        }
        res.redirect('/');
    });
});

app.get("/secrets", async function(req, res) {
    let foundUsers = await User.find({"secret": {$ne: null}});
    if (foundUsers) {
        console.log(foundUsers);
        res.render("secrets.ejs", {usersWithSecrets: foundUsers});
    }
});

app.get(
    '/auth/google',
    passport.authenticate('google', {
        scope: ['profile', 'email']
    })
);

app.get(
    '/auth/google/secrets',
    passport.authenticate('google', {
        successRedirect: '/secrets',
        failureRedirect: '/login'
    })
);

app.post(
    '/login',
    passport.authenticate('local', {
        successRedirect: '/secrets',
        failureRedirect: '/login'
    })
);

app.post('/register', async (req, res) => {
    const email = req.body.username;
    const password = req.body.password;
    const role = req.body.role;

    try {
        const user = await User.findOne({ email });
        if (user) {
            res.redirect('/login');
        } else {
            const hash = bcrypt.hash(password, process.env.SALTROUNDS);
            const newUser = new User({
                _id: new mongoose.Types.ObjectId(),
                email,
                password: hash,
                role
            });
            await newUser.save();
            req.login(newUser, (err) => {
                if (err) {
                    console.error('Error during login:', err);
                } else {
                    res.redirect('/secrets');
                }
            });
        }
    } catch (err) {
        console.log(err);
    }
});

app.get("/submit", function(req, res) {
    console.log(req.user, 'submitUser');
    if (req.isAuthenticated()) {
        res.render("submit.ejs");
    } else {
        res.redirect("/login");
    }
});

app.post('/submit', async function (req, res) {
    if (req.isAuthenticated()) {
        console.log(req.body);
        console.log(req.user, 'user');
        console.log(req.body.secret, 'secret');

        try {
            if (req.body && req.body.secret) {
                let updatedUser = await User.findOneAndUpdate(
                    { googleId: req.user.googleId },
                    { $set: { feedback: req.body.secret } },
                    { new: true } 
                );
                console.log(updatedUser, 'updatedUser');
                res.send('feedback updated');
            } else {
                res.status(400).json({ error: 'Bad Request. Missing secret in request body.' });
            }
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Internal Server Error' });
        }
    } else {
        res.status(401).json({ error: 'Unauthorized' });
    }
});

passport.use(
    'local',
    new Strategy(async function verify(email, password, cb) {
        try {
            const user = await User.findOne({ email: email });

            if (user) {
                const storedHashedPassword = user.password;
                const valid = bcrypt.compare(password, storedHashedPassword);

                if (valid) {
                    return cb(null, user);
                } else {
                    return cb(null, false);
                }
            } else {
                return cb('User not found');
            }
        } catch (err) {
            console.log(err, 'local error');
        }
    })
);

passport.use(
    'google',
    new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackURL: 'http://localhost:3000/auth/google/secret',
            userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo'
        },
        async (accessToken, refreshToken, profile, cb) => {
            try {
                console.log(accessToken);
                console.log(profile);
                const user = await User.findOne({ email: profile.email });

                if (!user) {
                    const newUser = new User({
                        email: profile.email,
                        googleId: profile.id
                    });
                    await newUser.save();
                    return cb(null, newUser);
                } else {
                    return cb(null, user);
                }
            } catch (err) {
                return cb(err);
            }
        }
    )
);

passport.serializeUser((user, cb) => {
    cb(null, user._id);
});

passport.deserializeUser(async (id, cb) => {
    try {
        const user = await User.findById(id);
        cb(null, user);
    } catch (err) {
        cb(err);
    }
});

app.post('/api/food/insert', async (req, res) => {
    try {
        const { id, foodTitle, foodContent, authorId, subscribedUserId, activeSubscriber } = req.body;
        if (req.body) {
            const newFood = new Food({ id, foodTitle, foodContent, authorId, subscribedUserId, activeSubscriber });
            await newFood.save();
            res.send('done and dusted');
        }
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.get('/getFood/:authorId', async (req, res) => {
    try { 
        const authorId = req.params.authorId;
        const cachedData = cache.get(authorId);

        if (cachedData) {
            console.log('Retrieving data from cache itself', cachedData);
            return res.json(cachedData);
        }
        const aggregationPipeline = [
            { $match: { activeSubscriber: true } },
            { 
                $group: {
                    _id: "$authorId",
                    totalBlogs: { $sum: 1 },
                    blogTitle: { $first: '$blogTitle' },
                    avgBlogLength: { $avg: { $strLenCP: "$blogContent" } }
                }
            },
            { $sort: { totalBlogs: -1 } },
            {
                $project: {
                    _id: 0,
                    authorId: "$_id",
                    totalBlogs: 1,
                    blogTitle: 1,
                    avgBlogLength: 1
                }
            }
        ];
        const aggregateData = await Food.aggregate(aggregationPipeline).exec();
        cache.set(authorId, aggregateData, 60);
        res.json(aggregateData);
    } catch (error) {
        console.log(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.delete('/api/food/deleteOne', async (req, res) => {
    try {
        if (req.body) {
            await Food.deleteOne(req.body);
        }
        res.json('deleted');
    } catch (error) {
        console.error('Error fetching notes:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.put('/api/food/updateOne/:id', async (req, res) => {
    try {  
        if (req.body) {
            await Food.findOneAndUpdate({ authorId: req.params.id }, req.body);
        }
        res.json('updated');
    } catch (error) {
        console.error('Error fetching notes:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.listen(3000, () => {
    console.log(`Server running on port ${3000}`);
});
