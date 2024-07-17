require("dotenv").config();
const path = require("path")
const express = require("express");
const mongoose = require("mongoose");
const book_router = require("./router/book_router");
const user_router = require("./router/user_router");
const PORT = process.env.PORT || 8000;
const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use("/bookstore", book_router)
app.use("/user", user_router)

mongoose.connect(process.env.DB_HOST);
let db = mongoose.connection;

db.once("open", () => {
  console.log("Connected to MongoDB");
});
db.on("error", (err) => {
  console.log("DB Error:" + err);
});

app.get("/", (req, res) => {
  res.redirect("/bookstore")
});

app.listen(PORT, () =>
  console.log(`Server started on http://127.0.0.1:${PORT}`)
);
