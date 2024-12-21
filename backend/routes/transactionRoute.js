const TransactionController = require("../controllers/TransactionController");

const express = require("express");
const router = express.Router();

router.post("/send", TransactionController.sendTokens);

module.exports = router;

