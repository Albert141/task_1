const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const { body, validationResult } = require('express-validator');

const app = express();
require('dotenv').config();

app.use(express.json());

mongoose.connect('mongodb://localhost:27017/task_1')
    .then(() => {
        console.log('Connected to MongoDB');
    })
    .catch((error) => {
        console.error('Error connecting to MongoDB:', error);
    });

    // Define User model
const User = mongoose.model('User', new mongoose.Schema({
    username: String,
    password: String
}));


// Define Post schema
const postSchema = new mongoose.Schema({
    title: String,
    body: String,
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    active: { type: Boolean, default: true },
    location: {
        type: { type: String, default: 'Point' },
        coordinates: [Number] // [longitude, latitude]
    }
});
postSchema.index({ location: '2dsphere' }); // Create a 2dsphere index on location field
const Post = mongoose.model('Post', postSchema);


const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET_KEY
};


// JWT Strategy
passport.use(new JwtStrategy(jwtOptions, (payload, done) => {
    User.findById(payload.sub)
        .then(user => {
            if (!user) {
                return done(null, false);
            }
            return done(null, user);
        })
        .catch(error => {
            return done(error, false);
        });
}));


// Registration API
app.post('/register', (req, res) => {
    const { username, password } = req.body;
    bcrypt.hash(password, 10)
        .then(hashedPassword => {
            const newUser = new User({ username, password: hashedPassword });
            return newUser.save();
        })
        .then(user => {
            res.status(201).json({ message: 'User registered successfully', user });
        })
        .catch(error => {
            res.status(400).json({ error: error.message });
        });
});

// Login API
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    User.findOne({ username })
        .then(user => {
            if (!user) {
                return res.status(401).json({ message: 'User not found' });
            }
            return bcrypt.compare(password, user.password)
                .then(isMatch => {
                    if (!isMatch) {
                        return res.status(401).json({ message: 'Incorrect password' });
                    }
                    const token = jwt.sign({ sub: user._id }, jwtOptions.secretOrKey);
                    res.json({ token });
                });
        })
        .catch(error => {
            res.status(500).json({ error: error.message });
        });
});


// Create a new post
app.post('/posts', passport.authenticate('jwt', { session: false }), [
    body('title').notEmpty().withMessage('Title is required'),
    body('body').notEmpty().withMessage('Body is required'),
    body('active').isBoolean().optional(), 
    body('location.coordinates').isArray({ min: 2, max: 2 }).withMessage('Location coordinates must be an array of length 2'),
    body('location.coordinates.*').isNumeric().withMessage('Coordinates must be numeric')
], (req, res) => {
    const { title, body, active, location } = req.body;
    const createdBy = req.user._id;
    const newPost = new Post({ title, body, active, createdBy, location });
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    newPost.save()
        .then(post => res.status(201).json({ message: 'Post created successfully', post }))
        .catch(error => res.status(400).json({ error: error.message }));
});


// Get all posts
app.get('/posts', passport.authenticate('jwt', { session: false }), (req, res) => {
    Post.find({ createdBy: req.user._id })
        .then(posts => res.json(posts))
        .catch(error => res.status(500).json({ error: error.message }));
});

// Update a post
app.put('/posts/:postId', passport.authenticate('jwt', { session: false }), (req, res) => {
    const { title, body, active, location } = req.body;
    Post.findOneAndUpdate(
        { _id: req.params.postId, createdBy: req.user._id },
        { $set: { title, body, active, location } },
        { new: true }
    )
        .then(post => {
            if (!post) {
                return res.status(404).json({ message: 'Post not found' });
            }
            res.json({ message: 'Post updated successfully', post });
        })
        .catch(error => res.status(400).json({ error: error.message }));
});

// Delete a post
app.delete('/posts/:postId', passport.authenticate('jwt', { session: false }), (req, res) => {
    Post.findOneAndDelete({ _id: req.params.postId, createdBy: req.user._id })
        .then(post => {
            if (!post) {
                return res.status(404).json({ message: 'Post not found' });
            }
            res.json({ message: 'Post deleted successfully', post });
        })
        .catch(error => res.status(400).json({ error: error.message }));
});

// Retrieve Posts by Location API
app.get('/posts/location', passport.authenticate('jwt', { session: false }), async (req, res) => {
    try {
        const { latitude, longitude } = req.query;

        if (!latitude || !longitude) {
            return res.status(400).json({ error: 'Latitude and longitude are required' });
        }

        const userLatitude = parseFloat(latitude);
        const userLongitude = parseFloat(longitude);

        const posts = await Post.find({
            createdBy: req.user._id,
            location: {
                $near: {
                    $geometry: {
                        type: 'Point',
                        coordinates: [userLongitude, userLatitude] 
                    }
                }
            }
        });

        res.json(posts);
    } catch (error) {
        console.error('Error retrieving posts:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});


app.get('/dashboard/posts/count', passport.authenticate('jwt', { session: false }), async (req, res) => {
    try {
        // Count active and inactive posts for the authenticated user
        const activeCount = await Post.countDocuments({ createdBy: req.user._id, active: true });
        const inactiveCount = await Post.countDocuments({ createdBy: req.user._id, active: false });

        res.json({ activeCount, inactiveCount });
    } catch (error) {
        console.error('Error getting post counts:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});


const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});


