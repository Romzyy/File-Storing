// user_router.js
const express = require("express");
const router = express.Router();
const path = require("path");
const User = require("../models/user");
const bcrypt = require("bcrypt");

const {
  validateUserSignup,
  validateUserLogin,
} = require("../middleware/validator");

const authMiddleware = require("../middleware/auth");

router
  .route("/login")
  .get((req, res) => {
    res.sendFile(path.join(__dirname, "../views", "login.html"));
  })
  .post(validateUserLogin, (req, res, next) => {
    const { email, password } = req.body;

    User.findOne({ email })
      .then((user) => {
        if (!user) {
          console.log(`User with email ${email} not found`);
          return res
            .status(400)
            .json({ error: `User with email ${email} not found` });
        }

        bcrypt.compare(password, user.password).then((isMatched) => {
          if (!isMatched) {
            return res
              .status(400)
              .json({ error: `Incorrect password for user ${email}` });
          }

          // Save user info in session
          req.session.user = {
            id: user._id,
            email: user.email,
            username: user.username,
            first_name: user.first_name,
          };

          // Save the session explicitly
          req.session.save((err) => {
            if (err) {
              console.error("Error saving to session storage: ", err);
              return next(new Error("Error saving session"));
            }
            console.log(
              `Hello ${user.first_name}, with username ${user.username} (${email}) logged in successfully`
            );
            res.json({
              message: `Hello ${user.first_name}, with username ${user.username} (${email}) logged in successfully`,
            });
          });
        });
      })
      .catch((error) => {
        console.error("Error during login:", error);
        res.status(500).json({ error: "Internal Server Error" });
      });
  });

// User signup
router
  .route("/sign-up")
  .get((req, res) => {
    res.sendFile(path.join(__dirname, "../views", "sign-up.html"));
  })
  .post(validateUserSignup, (req, res) => {
    const { first_name, last_name, username, email } = req.body;

    bcrypt
      .hash(req.body.password, 10)
      .then((hashedPassword) => {
        const newUser = new User({
          first_name,
          last_name,
          username,
          email,
          password: hashedPassword,
        });

        return newUser.save();
      })
      .then(() => {
        res.status(201).json({ message: "Successfully Added" });
      })
      .catch((err) => {
        console.error(err);
        res.status(500).json({ error: "Internal Server Error" });
      });
  });

// Check login status
router.get("/check-login", (req, res) => {
  if (req.session.user) {
    // If user session exists, return user data
    res.json({
      isLoggedIn: true,
      user: req.session.user,
    });
  } else {
    // If user session does not exist, return isLoggedIn false
    res.json({
      isLoggedIn: false,
    });
  }
});

// User logout
router.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error during logout:", err);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    res.json({ message: "Logged out successfully" });
  });
});

router.get("/api/users", authMiddleware, (req, res) => {
  User.find({}, { password: 0, createdAt: 0, updatedAt: 0, __v: 0 })
    .then((users) => {
      res.json(users);
    })
    .catch((err) => {
      console.error("Error fetching user list:", err);
      res.status(500).json({ error: "Internal Server Error" });
    });
});

router.get("/api/user/:id", authMiddleware, (req, res) => {
  User.findById(req.params.id, {
    password: 0,
    createdAt: 0,
    updatedAt: 0,
    __v: 0,
  })
    .then((user) => {
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      console.log(user);
      res.json(user);
    })
    .catch((err) => {
      console.error("Error fetching user data:", err);
      res.status(500).json({ error: "Internal Server Error" });
    });
});

module.exports = router;
