const express = require("express");
const app = express();
const path = require("path");
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

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

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
});

const User = mongoose.model("User", userSchema);

app.use(express.static(path.join(path.resolve(), "public")));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.set("view engine", "ejs");

const isAuthenticated = async (req, res, next) => {
  const { token } = req.cookies;

  if (token) {
    const decode = jwt.verify(token, "secretString");

    req.user = await User.findById(decode._id);

    next();
  } else {
    res.redirect("/login");
  }
};

app.get("/", isAuthenticated, (req, res) => {
  // res.sendFile(__dirname + "/index.html")
  // res.sendFile(path.join(path.resolve(), "/index.html"))
  // res.render("index", {name: 'Devang'});
  res.render("logout", { info: req.user });
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  let user = await User.findOne({ email });

  if (user) {
    return res.render("login");
  }

  const hashPswd = await bcrypt.hash(password, 10);

  user = await User.create({
    name,
    email,
    password: hashPswd,
  });

  const token = jwt.sign({ _id: user._id }, "secretString");

  res.cookie("token", token, {
    httpOnly: true,
  });
  res.redirect("/");
});

app.get("/login", (req, res) => {
    res.render("login");
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  let user = await User.findOne({ email });

  if (!user) {
    return res.redirect("/register");
  }

//   const isMatch = user.password === password;
  const isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch) {
    return res.render("login", { message: "Incorrect Password" });
  }

  const token = jwt.sign({ _id: user._id }, "secretString");

  res.cookie("token", token, {
    httpOnly: true,
  });
  res.redirect("/");
});

app.get("/logout", (req, res) => {
  res.cookie("token", null, {
    httpOnly: true,
    expires: new Date(Date.now()),
  });
  res.redirect("/");
});

app.listen(5000, () => {
  console.log("server running at 5000");
});
