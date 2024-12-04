const router = require('express').Router();
const User = require('../models/user.model');
const { body, validationResult } = require('express-validator');
const passport = require('passport');
const { ensureLoggedOut, ensureLoggedIn } = require('connect-ensure-login');
const { registerValidator } = require('../utils/validators');

// Login Route
router.get(
  '/login',
  ensureLoggedOut({ redirectTo: '/' }),
  async (req, res, next) => {
    res.render('login');
  }
);

router.post(
  '/login',
  ensureLoggedOut({ redirectTo: '/' }),
  passport.authenticate('local', {
    successReturnToOrRedirect: '/',
    failureRedirect: '/auth/login',
    failureFlash: true,
  })
);

// Register Route
router.get(
  '/register',
  ensureLoggedOut({ redirectTo: '/' }),
  async (req, res, next) => {
    res.render('register');
  }
);

router.post(
  '/register',
  ensureLoggedOut({ redirectTo: '/' }),
  [
    // Validation checks
    body('email', 'Invalid email').isEmail().normalizeEmail(),
    body('password', 'Password must be at least 6 characters long').isLength({ min: 6 }),
    body('password2', 'Passwords must match').custom((value, { req }) => value === req.body.password),
    body('name', 'Name is required').notEmpty(), // Add validation for name
  ],
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        errors.array().forEach((error) => {
          req.flash('error', error.msg);
        });
        res.render('register', {
          email: req.body.email,
          name: req.body.name, // Render name in case of errors
          messages: req.flash(),
        });
        return;
      }

      const { email, name } = req.body; // Get email and name
      const doesExist = await User.findOne({ email });
      if (doesExist) {
        req.flash('warning', 'Username/email already exists');
        res.redirect('/auth/register');
        return;
      }

      // Create a new user
      const user = new User({
        email,
        password: req.body.password, // Assuming password hashing will be done in the User model
        name, // Save name to database
      });
      await user.save();

      req.flash(
        'success',
        `${user.email} registered successfully, you can now login`
      );
      res.redirect('/auth/login');
    } catch (error) {
      next(error);
    }
  }
);

// Logout Route
router.get(
  '/logout',
  ensureLoggedIn({ redirectTo: '/' }),
  async (req, res, next) => {
    req.logout();
    res.redirect('/');
  }
);

// Edit Profile Route (GET)
router.get(
  '/edit-profile',
  ensureLoggedIn({ redirectTo: '/' }),
  async (req, res, next) => {
    try {
      const user = await User.findById(req.user.id);
      res.render('edit-profile', { user });
    } catch (error) {
      next(error);
    }
  }
);

// Edit Profile Route (POST) to handle form submission
router.post(
  '/edit-profile',
  ensureLoggedIn({ redirectTo: '/' }),
  [
    // Validation for name and email
    body('email', 'Invalid email').isEmail().normalizeEmail(),
    body('name', 'Name is required').notEmpty(),
  ],
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        errors.array().forEach((error) => {
          req.flash('error', error.msg);
        });
        const user = await User.findById(req.user.id);
        return res.render('edit-profile', {
          user,
          messages: req.flash(),
        });
      }

      const { email, name } = req.body;
      const user = await User.findById(req.user.id);

      // Check if the email is being updated and if it already exists
      if (email !== user.email) {
        const emailExists = await User.findOne({ email });
        if (emailExists) {
          req.flash('error', 'Email is already in use');
          return res.redirect('/auth/edit-profile');
        }
      }

      // Update user data
      user.email = email;
      user.name = name;
      await user.save();

      req.flash('success', 'Profile updated successfully');
      res.redirect('/');

    } catch (error) {
      next(error);
    }
  }
);

module.exports = router;
