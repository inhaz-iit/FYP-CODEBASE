const WalletController = require("../controllers/WalletController");

const express = require("express");
const router = express.Router();

router.post("/create", WalletController.createWallet);
router.post("/connect-sepolia", WalletController.connectSepolia);
router.post("/send", WalletController.sendTokens);


module.exports = router;

