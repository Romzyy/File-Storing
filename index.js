require("dotenv").config();
const path = require("path");
const express = require("express");
const session = require("express-session"); //new
const MongoStore = require("connect-mongo"); //new
const mongoose = require("mongoose");

const app = express();

const PORT = process.env.PORT || 8000;
// Configure session middleware
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    store: MongoStore.create({
      mongoUrl: process.env.DB_HOST,
      collectionName: "sessions",
      ttl: 5, // this is in seconds
    }),
    cookie: { maxAge: 1000 * 5 }, // maxAge: 1000 * 60 * 60 * 24 1 day
  })
);
const book_router = require("./router/book_router");
const user_router = require("./router/user_router");

// Connect to MongoDB
mongoose.connect(process.env.DB_HOST);
let db = mongoose.connection;

db.once("open", () => {
  console.log("Connected to MongoDB");
});
db.on("error", (err) => {
  console.log("DB Error:" + err);
});

// Application level middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use("/bookstore", book_router);
app.use("/user", user_router);

app.get("/test-session", (req, res) => {
  if (req.session.views) {
    console.log(req.session);
    req.session.views++;
    res.setHeader("Content-Type", "text/html");
    res.write("<p>Views: " + req.session.views + "</p>");
    res.end();
  } else {
    req.session.views = 1;
    res.end("Welcome to the session demo. Refresh!");
  }
});

app.get("/", (req, res) => {
  res.redirect("/user/login");
});

app.listen(PORT, () =>
  console.log(`Server started on http://127.0.0.1:${PORT}`)
);
