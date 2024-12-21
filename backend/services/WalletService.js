const WalletModel = require("../models/walletModel");
const config = require("../configuration/config");
const { Wallet, JsonRpcProvider, formatEther} = require("ethers");

class WalletService {
    async createWallet(walletParams,res) {
        // Generate a new Ethereum wallet
        const wallet = Wallet.createRandom();
        const data = new WalletModel({
            address: wallet.address,
            privateKey: wallet.privateKey,
            publicKey: wallet.publicKey,
            mnemonic: wallet.mnemonic,
            chainCode: wallet.chainCode,
            path: wallet.path,
            index: wallet.index,
            depth: wallet.depth,
            network: wallet.network || "Ethereum Mainnet",
            wallet: wallet
        });
        
        const walletData = await data.save();

        return {
            message: "Wallet created successfully", 
            wallet: walletData
        };
    }

    async connectSepolia(walletParams,res) {
        // connecting to Sepolia Testnet
        const walletData = await WalletModel.findById(walletParams.walletID);
        
        // Configure the provider
        const provider = new JsonRpcProvider(config.SEPOLIA_RPC); 

        // Get the balance in Wei (smallest denomination of ETH)
        const balanceWei = await provider.getBalance(walletData.address);
        
        // Convert balance from Wei to Ether
        const balanceEth = formatEther(balanceWei);

        console.log(balanceEth);
    }

    async sendTokens(req, res) {
        try {
            const { senderPrivateKey, recipient } = req.body;
    
            if (!senderPrivateKey || !recipient) {
                return res.status(400).json({ error: "Missing required parameters" });
            }
    
            const provider = new JsonRpcProvider(config.SEPOLIA_RPC);
            const senderWallet = new Wallet(senderPrivateKey, provider);
    
            // Fetch fee data
            const feeData = await provider.getFeeData();
            console.log("Fee Data:", feeData);
    
            // Gas calculation using BigInt
            const gasLimit = 21000n; // Gas limit for a simple ETH transfer
            const gasPrice = feeData.maxFeePerGas || feeData.gasPrice;; // Use BigInt for gasPrice
            const gasCost = gasPrice * gasLimit; // Total gas cost in wei (BigInt arithmetic)
            console.log(gasCost.toString());

            // Check sender's balance
            const balance = await provider.getBalance(senderWallet.address);
            console.log("Sender Balance:", balance.toString());
    
            if (balance <= gasCost) {
                return res.status(400).json({ error: "Insufficient balance for gas fees" });
            }
    
            // Calculate the amount to send
            // const amountToSend = balance - gasCost;
            const BUFFER = 1500n; // Reserve a buffer of 1000 wei
            console.log("balance => " + balance.toString());
            console.log("gas cost => " + gasCost.toString());
            console.log("Buffer => " + BUFFER.toString());
            const maxSendableAmount = balance - gasCost - BUFFER;
            console.log("Max Sendable Amount -> ", maxSendableAmount.toString());
            console.log("Variation  => ", (maxSendableAmount + gasCost + BUFFER).toString());
            // Create and send transaction
            const tx = {
                to: recipient,
                value: maxSendableAmount, // Amount in wei
            };
    
            console.log("Transaction Object:", tx);
    
            // Sign and send the transaction
            const txResponse = await senderWallet.sendTransaction(tx);
            const receipt = await txResponse.wait();
    
            return res.status(200).json({
                message: "Transaction successful",
                transactionHash: receipt.transactionHash,
                blockNumber: receipt.blockNumber,
                amountSent: formatEther(maxSendableAmount), // Convert to ETH for readability
            });
        } catch (error) {
            console.error("Error sending Ether:", error);
    
            if (!res.headersSent) {
                return res.status(500).json({ error: error.message });
            }
        }
    }
}
  
module.exports = WalletService;
