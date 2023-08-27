// Import necessary packages
const express = require("express");
const app = express();
const path = require("path");
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

// Connect to MongoDB database
mongoose
  .connect("mongodb://localhost:27017", {
    dbName: "backend",
  })
  .then((res) => {
    console.log("Database connected");
  })
  .catch((err) => {
    console.log(err);
  });

// Define User schema for MongoDB
const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
});

// Create User model based on schema
const User = mongoose.model("User", userSchema);

// Set up middleware and configurations
app.use(express.static(path.join(path.resolve(), "public"))); // Serve static files from 'public' directory
app.use(express.urlencoded({ extended: true })); // Parse URL-encoded request bodies
app.use(cookieParser()); // Parse cookies
app.set("view engine", "ejs"); // Set EJS as the view engine

// Middleware to check if user is authenticated
const isAuthenticated = async (req, res, next) => {
  const { token } = req.cookies;

  if (token) {
    const decode = jwt.verify(token, "secretString");

    // Attach user information to the request
    req.user = await User.findById(decode._id);

    next(); // Continue to the next middleware or route handler
  } else {
    res.redirect("/login"); // Redirect to login page if not authenticated
  }
};

// Route for the main page (requires authentication)
app.get("/", isAuthenticated, (req, res) => {
  res.render("logout", { info: req.user }); // Render the 'logout' view and pass user information
});

// Route for user registration form
app.get("/register", (req, res) => {
  res.render("register"); // Render the 'register' view
});

// Handle user registration form submission
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  let user = await User.findOne({ email });

  if (user) {
    return res.render("login"); // Redirect to login page if user already exists
  }

  const hashPswd = await bcrypt.hash(password, 10);

  // Create a new user with hashed password
  user = await User.create({
    name,
    email,
    password: hashPswd,
  });

  const token = jwt.sign({ _id: user._id }, "secretString");

  // Set the JWT token in a cookie and redirect to main page
  res.cookie("token", token, {
    httpOnly: true,
  });
  res.redirect("/");
});

// Route for login page
app.get("/login", (req, res) => {
  res.render("login"); // Render the 'login' view
});

// Handle user login form submission
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  let user = await User.findOne({ email });

  if (!user) {
    return res.redirect("/register"); // Redirect to registration page if user does not exist
  }

  const isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch) {
    return res.render("login", { message: "Incorrect Password" }); // Render login page with error message
  }

  const token = jwt.sign({ _id: user._id }, "secretString");

  // Set the JWT token in a cookie and redirect to main page
  res.cookie("token", token, {
    httpOnly: true,
  });
  res.redirect("/");
});

// Route for logging out
app.get("/logout", (req, res) => {
  // Clear the token cookie and redirect to main page
  res.cookie("token", null, {
    httpOnly: true,
    expires: new Date(Date.now()),
  });
  res.redirect("/");
});

// Start the server
app.listen(5000, () => {
  console.log("server running at 5000");
});
