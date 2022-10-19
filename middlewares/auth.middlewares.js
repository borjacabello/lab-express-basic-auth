// Authentication middleware to execute as a callback in routes implementation
const isLoggedIn = (req, res, next) => {
    if (req.session.user === undefined) {
        res.redirect("auth/login");
    } else {
        next()
    }
}

// Export as an object, different middlewares can be created
module.exports = {
    isLoggedIn
}