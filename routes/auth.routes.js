const router = require("express").Router();
const User = require("../models/User.model");
const bcrypt = require("bcryptjs");

//* Authentication routes => Sign Up & Log In

//* Sign Up Routes
// GET "/auth/signup" => Register form view rendering
router.get("/signup", (req, res, next) => {
  res.render("auth/signup.hbs");
});

// POST "/auth/signup" => Receiving of User Info and creation of the new user in the DB
router.post("/signup", async (req, res, next) => {
  const { username, password } = req.body;

  // Validation 1: Registration form fields can't be empty
  if (username === "" || password === "") {
    res.render("auth/signup.hbs", {
      errorMessage: "Registration fields can't be empty!",
    });
    return;
  }

  // Validation 2: Password - At least 8 characters, 1 uppercase letter, 1 number
  const passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,}$/gm;
  if (!passwordRegex.test(password)) {
    res.render("auth/signup.hbs", {
      errorMessage:
        "Password should contain 8 characters, 1 uppercase letter and 1 number at least",
    });
    return;
  }

  try {
    // Async Validation 3: Unique user (username) in the DB/application
    const userInDatabase = await User.findOne({ username: username });
    if (userInDatabase !== null) {
      res.render("auth/signup.hbs", {
        errorMessage: "Username already exists in the database!",
      });
      return;
    }

    // Password Encrypting -- Async way
    const salt = await bcrypt.genSalt(12);
    const hashPassword = await bcrypt.hash(password, salt);

    // User registration info
    const userInfo = {
      username,
      password: hashPassword,
    };

    // User creation after validations
    await User.create(userInfo);

    res.redirect("/auth/login");
  } catch (error) {
    next(error);
  }
});


//* Log In routes
// GET "/auth/login" => User Access form view rendering
router.get("/login", (req, res, next) => {
  res.render("auth/login.hbs");
});

// POST "/auth/login" => Receiving of User Info credentials and validation
router.post("/login", async (req, res, next) => {
  const { username, password } = req.body;

  // Validation 1: Log in form fields can't be empty
  if (username === "" || password === "") {
    res.render("auth/login.hbs", {
      errorMessage: "Registration fields can't be empty!",
    });
    return;
  }

  // Validation 2: Password - At least 8 characters, 1 uppercase letter, 1 number
  const passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,}$/gm;
  if (!passwordRegex.test(password)) {
    res.render("auth/login.hbs", {
      errorMessage:
        "Password should contain 8 characters, 1 uppercase letter and 1 number at least",
    });
    return;
  }

  try {
    // Async Validation 3: username exists and is equal to the one created in the DB
    const existingUser = await User.findOne({ username: username });
    if (existingUser === null) {
      res.render("auth/login.hbs", {
        errorMessage: "Incorrect credentials!",
      });
      return;
    }

    // Async Validation 4: log in password is equal to the one in the DB user
    const passwordCheck = await bcrypt.compare(password, existingUser.password);
    if (!passwordCheck) {
      // if not found (passwordCheck === false)
      res.render("auth/login.hbs", {
        errorMessage: "Incorrect credentials!",
      });
      return;
    }

    // Create a new Session/Cookie
    req.session.user = existingUser;

    // To make sure session has been properly created, save the session before redirection
    req.session.save(() => {
        // Redirect to /profile if session has been saved
        res.redirect("/profile/main")
    })

  } catch (error) {
    next(error);
  }
});


//* Log Out route
// GET "/auth/logout" => Closes the opened session (destroys it)
router.get("/logout", (req, res, next) => {
    req.session.destroy(() => {
        res.redirect("/")
    })
})

module.exports = router;
