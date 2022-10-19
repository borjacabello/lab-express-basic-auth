const router = require("express").Router();
const User = require("../models/User.model");
const bcrypt = require("bcryptjs");

//* Authentication routes => Sign Up & Log In

// GET "/auth/signup" => Register form view rendering
router.get("/signup", (req, res, next) => {
  res.render("auth/signup.hbs");
});

// POST "/auth/signup" => Receiving of User Info and creation of the new user in the DB
router.post("/signup", async (req, res, next) => {
  const { username, password } = req.body;

  try {
    // Validation 1: Registration form fields can't be empty
    if (username === "" || password === "") {
      res.render("auth/signup.hbs", {
        errorMessage: "Registration fields can't be empty!",
      });
      return;
    }

    // Validation 2: Unique user (username) in the DB/application
    const userInDatabase = await User.findOne({ username: username });
    if (userInDatabase !== null) {
      res.render("auth/signup.hbs", {
        errorMessage: "Username already exists in the database!",
      });
      return;
    }

    // Validation 3: Password - At least 8 characters, 1 uppercase letter, 1 number
    const passwordRegex =
      /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,}$/gm;
    if (!passwordRegex.test(password)) {
      res.render("auth/signup.hbs", {
        errorMessage:
          "Password should contain 8 characters, 1 uppercase letter and 1 number at least",
      });
      return;
    }

    // Password Encrypting -- Async way
    const salt = await bcrypt.genSalt(12);
    const hashPassword = await bcrypt.hash(password, salt);

    // User registration info
    const userInfo = {
      username,
      password: hashPassword
    };

    // User creation after validations
    await User.create(userInfo);

    res.redirect("/auth/login");
  } catch (error) {
    next(error);
  }
});

module.exports = router;
