const express = require("express");
const router = express.Router();
const path = require("path");
const Book = require("../models/book");
const { validateBook } = require("../middleware/validator");

router.get("/", (req, res) => {
  // console.log(req.session)
  res.sendFile(path.join(__dirname, "../views", "book_list.html"));
});

router.get("/api/books", (req, res) => {
  Book.find({})
    .then((books) => {
      res.json(books);
    })
    .catch((error) => {
      console.error("Error:", error);
      res.status(500).json({ error: "Internal Server Error" });
    });
});

// add route
router
  .route("/add")
  .get((req, res) => {
    res.sendFile(path.join(__dirname, "../views/book_add.html"));
  })
  .post(validateBook, (req, res) => {
    let book = new Book();
    book.title = req.body.title;
    book.author = req.body.author;
    book.pages = req.body.pages;
    book.genres = req.body.genres;
    book.rating = req.body.rating;

    book
      .save()
      .then(() => {
        res.json({ message: "Successfully Added" });
      })
      .catch((err) => {
        console.error(err);
        res.status(500).json({ error: "Internal Server Error" });
      });
  });

// id search
router.route("/api/book/:id").get((req, res) => {
  Book.findById(req.params.id)
    .then((book) => {
      if (!book) {
        return res.status(404).json({ error: "Book not found" });
      }
      res.json({ book: book });
    })
    .catch((err) => {
      console.error("Error fetching book by id:", err);
      res.status(500).json({ error: "Internal Server Error" });
    });
});

router
  .route("/book/:id")
  .get((req, res) => {
    res.sendFile(path.join(__dirname, "../views", "book.html"));
  })
  .delete((req, res) => {
    const query = { _id: req.params.id };

    Book.deleteOne(query)
      .then((result) => {
        if (result.deletedCount > 0) {
          res.json({ success: true, message: "Successfully Deleted" });
        } else {
          res.status(404).json({ error: "Book not found" });
        }
      })
      .catch((err) => {
        console.error("Error deleting book by id:", err);
        res.status(500).json({ error: "Internal Server Error" });
      });
  });

// edit book route
router.get("/edit/:id", (req, res) => {
  res.sendFile(path.join(__dirname, "../views", "book_edit.html"));
});

router
  .route("/api/book/edit/:id")
  .get((req, res) => {
    Book.findById(req.params.id)
      .then((book) => {
        if (!book) {
          return res.status(404).json({ error: "Book not found" });
        }
        res.json({ book: book });
      })
      .catch((err) => {
        console.error("Error fetching book by id:", err);
        res.status(500).json({ error: "Internal Server Error" });
      });
  })
  .post((req, res) => {
    let updatedBook = {
      title: req.body.title,
      author: req.body.author,
      pages: req.body.pages,
      genres: req.body.genres,
      rating: req.body.rating,
    };

    const query = { _id: req.params.id };

    Book.updateOne(query, updatedBook)
      .then(() => {
        res.json({ message: "Successfully Updated" });
      })
      .catch((err) => {
        console.error("Error updating book by id:", err);
        res.status(500).json({ error: "Internal Server Error" });
      });
  });

module.exports = router;
