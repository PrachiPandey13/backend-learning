const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const User = require("../models/User");

const register = (req, res) => {
  const { email, password } = req.body;

  // Check if the user already exists
  if (User.findByEmail(email)) {
    return res.status(400).json({ message: "User already exists" });
  }

  const newUser = User.create(email, password);

  // Generate a JWT token
  const token = jwt.sign({ email: newUser.email }, process.env.JWT_SECRET, { expiresIn: "1h" });

  res.status(201).json({ message: "User registered successfully", token });
};

const login = (req, res) => {
  const { email, password } = req.body;

  const user = User.findByEmail(email);

  // Check if the user exists
  if (!user) {
    return res.status(400).json({ message: "Invalid credentials" });
  }

  // Check if the password is correct
  const isMatch = bcrypt.compareSync(password, user.password);
  if (!isMatch) {
    return res.status(400).json({ message: "Invalid credentials" });
  }

  // Generate a JWT token
  const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET, { expiresIn: "1h" });

  res.status(200).json({ message: "Login successful", token });
};

const logout = (req, res) => {
  res.status(200).json({ message: "User logged out successfully" });
};

module.exports = { register, login, logout };
