module.exports = (req, res, next) => {
  if (req.session && req.session.user) {
    next(); // User is logged in, proceed to the next middleware/route handler
  } else {
    res.status(401).json({ message: "Unauthorized: Please log in" });
  }
};
