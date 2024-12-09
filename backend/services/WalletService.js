const { Wallet } = require("ethers");
const WalletModel = require("../models/walletModel");
const { JsonRpcProvider , formatEther} = require("ethers");
const config = require("../configuration/config");

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
}
  
module.exports = WalletService;
