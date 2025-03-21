const UserController = require("../controllers/UserController");

const express = require("express");
const router = express.Router();

router.post("/register", UserController.userRegistration);
router.post("/login", UserController.userLogin);

module.exports = router;

