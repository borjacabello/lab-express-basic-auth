const router = require("express").Router();
const User = require("../models/User.model");

const { isLoggedIn } = require("../middlewares/auth.middlewares.js");

// GET "/profile/main" => Renders main profile page if session has been opened
router.get("/main", isLoggedIn, async (req, res, next) => {
  try {
    const currentActiveUser = await User.findById(req.session.user._id);

    res.render("profile/main.hbs", {
      userDetails: currentActiveUser,
    });
  } catch (error) {
    next(error);
  }
});

// GET "/profile/private" => Renders private info page if session has been opened
router.get("/private", isLoggedIn, (req, res, next) => {
  res.render("profile/private.hbs");
});

module.exports = router;
