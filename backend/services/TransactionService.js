const config = require("../configuration/config");
const lockContractABI = require("../blockchain/ABI/LockTokenABI")
const tokenContractABI = require("../blockchain/ABI/ZKPridgeCoinABI")
const { ethers } = require("ethers");

class TransactionService {
    async sendTokens(walletParams,res) {
        const lockContractResponse = await this.lockTokensInContract(walletParams);
        const mintContractResponse = await this.mintTokensInContract(walletParams);
        console.log(lockContractResponse);
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
    
            console.log("Test");
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
        
    }
}
  
module.exports = TransactionService;
