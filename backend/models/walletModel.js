const mongoose = require("mongoose");

const walletSchema = new mongoose.Schema({
    address: {
        type: String,
        required: true,
        unique: true, // Ensure no duplicate addresses
        index: true, // Index for faster querying
    },
    privateKey: {
        type: String,
        required: true, // Handle securely in production (encrypt if necessary)
    },
    publicKey: {
        type: String,
        required: true,
    },
    mnemonic: {
        phrase: {
            type: String,
            required: true,
        },
        password: {
            type: String,
            default: "", // Empty if no password is set
        },
        entropy: {
            type: String,
            required: true,
        },
        wordlist: {
            locale: {
                type: String,
                default: "en",
            },
        },
    },
    chainCode: {
        type: String,
    },
    path: {
        type: String,
        required: true,
    },
    index: {
        type: Number,
        default: 0,
    },
    depth: {
        type: Number,
        default: 0,
    },
    network: {
        type: String,
        default: "Ethereum Mainnet", // Default to Ethereum Mainnet
        enum: ["Ethereum Mainnet", "Sepolia Testnet", "Goerli Testnet", "Other"], // Add other networks as needed
    },
    createdAt: {
        type: Date,
        default: Date.now,
    },
    wallet: {
        type: Object,
    },
});

module.exports = mongoose.model("Wallet-Model", walletSchema);