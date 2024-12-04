const User = require('../models/user.model');
const router = require('express').Router();
const mongoose = require('mongoose');
const { roles } = require('../utils/constants');
const bcrypt = require('bcrypt'); // Ensure bcrypt is required at the top of the file

// Route to manage users page
router.get('/users', async (req, res, next) => {
  try {
    const users = await User.find().select('id name email role isActive'); // Include name field
    res.render('manage-users', { users });
  } catch (error) {
    next(error);
  }
});

// Route to view a user's profile
router.get('/user/:id', async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      req.flash('error', 'Invalid ID');
      res.redirect('/admin/users');
      return;
    }
    const person = await User.findById(id).select('id name email role isActive');
    res.render('profile', { person });
  } catch (error) {
    next(error);
  }
});

// Route to add a new user
router.get('/add-user', (req, res) => {
  res.render('add-user');
});

// Route to handle the Add User form submission
router.post('/add-user', async (req, res, next) => {
  try {
    const { username, email, password, role } = req.body;
    console.log('Incoming data:', req.body);

    // Validate all fields are filled
    if (!username || !email || !password || !role) {
      req.flash('error', 'All fields are required');
      return res.redirect('/admin/add-user');
    }

    // Check if the email already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      req.flash('error', 'A user with this email already exists');
      return res.redirect('/admin/add-user');
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user instance
    const newUser = new User({
      name: username, // Save the username as 'name' in the database
      email,
      password: hashedPassword, // Store the hashed password
      role,
      isActive: true, // Default status for a new user
    });

    // Save the user to the database
    await newUser.save();

    req.flash('success', `User ${username} (${email}) added successfully`);
    res.redirect('/admin/users'); // Redirect to the users management page
  } catch (error) {
    console.error('Error adding user:', error);
    req.flash('error', 'An error occurred while adding the user');
    res.redirect('/admin/add-user');
  }
});

// Route to delete a user
router.post('/delete-user', async (req, res, next) => {
  try {
    const { id } = req.body;

    // Validate if ID is valid
    if (!mongoose.Types.ObjectId.isValid(id)) {
      req.flash('error', 'Invalid ID');
      return res.redirect('/admin/users');
    }

    // Prevent admins from deleting themselves
    if (req.user.id === id) {
      req.flash('error', 'Admins cannot delete themselves');
      return res.redirect('back');
    }

    // Find and delete the user
    const deletedUser = await User.findByIdAndDelete(id);

    if (!deletedUser) {
      req.flash('error', 'User not found');
      return res.redirect('/admin/users');
    }

    req.flash('success', `User ${deletedUser.email} deleted successfully`);
    res.redirect('/admin/users');
  } catch (error) {
    next(error);
  }
});

// Route to toggle activation status
router.post('/toggle-activation', async (req, res, next) => {
  try {
    const { id } = req.body;

    // Validate if ID is valid
    if (!mongoose.Types.ObjectId.isValid(id)) {
      req.flash('error', 'Invalid ID');
      return res.redirect('back');
    }

    const user = await User.findById(id);
    if (!user) {
      req.flash('error', 'User not found');
      return res.redirect('back');
    }

    // Toggle the active status
    user.isActive = !user.isActive;
    await user.save();

    const status = user.isActive ? 'activated' : 'deactivated';
    req.flash('success', `User ${user.email} ${status} successfully`);
    res.redirect('back');
  } catch (error) {
    next(error);
  }
});

// Route to show the edit form for a user
router.get('/edit-user/:id', async (req, res, next) => {
  try {
    const { id } = req.params;

    // Validate if ID is valid
    if (!mongoose.Types.ObjectId.isValid(id)) {
      req.flash('error', 'Invalid ID');
      return res.redirect('/admin/users');
    }

    const user = await User.findById(id);

    if (!user) {
      req.flash('error', 'User not found');
      return res.redirect('/admin/users');
    }

    res.render('edit-user', { user });
  } catch (error) {
    next(error);
  }
});

// Route to update user details (name, email, and role)
router.post('/update-user', async (req, res, next) => {
  try {
    const { id, name, email, role } = req.body;

    // Validate if ID is valid (should use _id for MongoDB)
    if (!mongoose.Types.ObjectId.isValid(id)) {
      req.flash('error', 'Invalid ID');
      return res.redirect('/admin/users');
    }

    // Check if email is already in use by another user
    const existingUser = await User.findOne({ email });
    if (existingUser && existingUser._id.toString() !== id) { // Change id to _id for MongoDB
      req.flash('error', 'Email is already in use by another user');
      return res.redirect(`/admin/edit-user/${id}`);
    }

    // Validate the role
    const rolesArray = Object.values(roles);
    if (!rolesArray.includes(role)) {
      req.flash('error', 'Invalid role selected');
      return res.redirect(`/admin/edit-user/${id}`);
    }

    // Update user details
    const user = await User.findByIdAndUpdate(
      id,
      { name, email, role },
      { new: true, runValidators: true }
    );

    req.flash('success', `User ${user.email} updated successfully`);
    res.redirect('/admin/users');
  } catch (error) {
    next(error);
  }
});

module.exports = router;
