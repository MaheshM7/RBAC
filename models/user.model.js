const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const createHttpError = require('http-errors');
const { roles } = require('../utils/constants');

const UserSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    lowercase: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  role: {
    type: String,
    enum: [roles.admin, roles.moderator, roles.client],
    default: roles.client,
  },
  isActive: {
    type: Boolean,
    default: true, // By default, users are active
  },
  name: { // New field added for name
    type: String,
    required: true, // Make the name field required
  },
});

// Hash the password and set default role for admin
UserSchema.pre('save', async function (next) {
  try {
    if (this.isNew) {
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(this.password, salt);
      this.password = hashedPassword;

      // Assign admin role to the configured admin email
      if (this.email === process.env.ADMIN_EMAIL.toLowerCase()) {
        this.role = roles.admin;
      }
    }
    next();
  } catch (error) {
    next(error);
  }
});

// Compare entered password with hashed password
UserSchema.methods.isValidPassword = async function (password) {
  try {
    return await bcrypt.compare(password, this.password);
  } catch (error) {
    throw createHttpError.InternalServerError(error.message);
  }
};

// Toggle user activation status
UserSchema.methods.toggleActivation = async function () {
  try {
    this.isActive = !this.isActive;
    await this.save();
  } catch (error) {
    throw createHttpError.InternalServerError('Failed to toggle activation status.');
  }
};

const User = mongoose.model('user', UserSchema);
module.exports = User;
