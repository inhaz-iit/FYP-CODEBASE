const config = require("../configuration/config");
const lockContractABI = require("../blockchain/ABI/LockTokenABI")
const tokenContractABI = require("../blockchain/ABI/ZKPridgeCoinABI")
const mintContractABI = require("../blockchain/ABI/MintTokenABI")
const { ethers } = require("ethers");

class TransactionService {
    async sendTokens(walletParams,res) {
        const lockContractResponse = await this.lockTokensInContract(walletParams);
        const mintContractResponse = await this.mintTokensInContract(walletParams);
        return {
            "Message":"Tokens locked and minted successfully",
            "Lock Contract Response": lockContractResponse,
            "Mint Contract Response": mintContractResponse
        };
    }

    async lockTokensInContract(walletParams) {
        const { amount, destinationAddress } = walletParams;
        const lockContractAddress = config.LOCK_CONTRACT_ADDRESS;
        const tokenContractAddress = config.TOKEN_ADDRESS;
        const sourceRpcUrl = config.SEPOLIA_RPC;

        // Initialize provider and signer
        const provider = new ethers.JsonRpcProvider(sourceRpcUrl);
        const signer = new ethers.Wallet(config.SENDER_PRIVATE_KEY, provider);

        // ABI for LockContract
        const lockContract = new ethers.Contract(lockContractAddress, lockContractABI, signer);
        const tokenContract = new ethers.Contract(tokenContractAddress, tokenContractABI, signer);

        try{
            // Step 1: Approve the LockContract to transfer user's tokens
            console.log("Approving LockContract to spend tokens...");
            const approveTx = await tokenContract.approve(
                lockContractAddress, 
                ethers.parseUnits(amount.toString(), 18) // Convert amount to wei
            );
    
            await approveTx.wait();
            console.log("Tokens approved successfully!");
    
            // Step 2: Lock Tokens in LockContract
            console.log(`Locking ${amount} tokens to destination: ${destinationAddress}`);
            const tx = await lockContract.lockTokens(
                ethers.parseUnits(amount.toString(), 18), 
                destinationAddress
            );
            
            const receipt = await tx.wait();
    
            console.log("Tokens locked successfully. TX Hash:", receipt.hash);
            return receipt.hash; // Return transaction hash
        } catch (error) {
            console.error("Error while locking tokens:", error);
            throw new Error("Error while locking tokens");
        }
    }

    async mintTokensInContract(walletParams) {
        const { amount, destinationAddress } = walletParams;

        // Mint contract and token configurations
        const mintContractAddress = config.MINT_CONTRACT_ADDRESS;
        const destinationRpcUrl = config.AMOY_RPC;

        // Initialize provider and signer for destination chain
        const provider = new ethers.JsonRpcProvider(destinationRpcUrl);
        const signer = new ethers.Wallet(config.PRIVATE_KEY, provider);

        const mintContract = new ethers.Contract(
            mintContractAddress,
            mintContractABI,
            signer
        );

        try {
            console.log(`Minting ${amount} tokens to address: ${destinationAddress}`);

            // Convert amount to Wei
            const mintTx = await mintContract.mintTokens(
                destinationAddress,
                ethers.parseUnits(amount.toString(), 18)
            );

            const receipt = await mintTx.wait();
            console.log("Tokens minted successfully. TX Hash:", receipt.hash);

            return receipt.hash;
        } catch (error) {
            console.error("Error while minting tokens:", error);
            throw new Error("Error while minting tokens");
        }
    }
}
  
module.exports = TransactionService;
