const config = require("../configuration/config");
const lockContractABI = require("../blockchain/ABI/LockTokenABI");
const tokenContractABI = require("../blockchain/ABI/ZKPridgeCoinABI");
const mintContractABI = require("../blockchain/ABI/MintTokenABI");
const CircuitABI = require("../blockchain/ABI/CircuitABI");
const { ethers } = require("ethers");
const { Contract, Provider, constants, hash, num } = require("starknet");

class TransactionService {
    constructor() {
        // Initialize StarkNet provider
        this.starkProvider = new Provider({     
            sequencer: { network: config.STARKNET_NETWORK }
        });
        
        // Initialize STARK verification contract
        this.starkContract = new Contract(
            CircuitABI,
            config.STARK_CONTRACT_ADDRESS,
            this.starkProvider
        );
    }

    async sendTokens(walletParams,res) {
        try{    
            // const lockContractResponse = await this.lockTokensInContract(walletParams);

            const proofResult = await this.generateAndVerifyProof(walletParams, "0x1234567890abcdef"); // Replace with actual lock transaction hash
                
            if (!proofResult.verified) {
                throw new Error("STARK proof verification failed");
            }

            // const mintContractResponse = await this.mintTokensInContract(walletParams);
            // return {
            //     "Message":"Tokens locked and minted successfully",
            //     "Lock Contract Response": lockContractResponse,
            //     "Proof Verification": proofResult,
            //     "Mint Contract Response": mintContractResponse
            // };
            return {
                "Message":"Tokens locked and minted successfully",
                "Proof Verification": proofResult
            };
        } catch (error) {
            console.error("Error in sendTokens:", error);
            throw error;
        }
    }

    async generateAndVerifyProof(walletParams, lockTxHash) {
        try {
            // Convert amount to hex string
            const amountInWei = ethers.parseUnits(walletParams.amount.toString(), 18);
            // const amountBN = number.toBN(amountInWei.toString());

            // Create message hash using pedersen
            const messageHash = hash.pedersen([
                num.hexToDecimalString(lockTxHash),
                amountStr
            ])

            // Prepare public input
            const publicInput = {
                message_hash: messageHash,
                public_key: number.toHex(number.toBN("0xA3F3b3f28C537a151527203deA65D40F45F86661")),
                signature: await this.generateSignature(messageHash)
            };

            // Prepare private input with proper conversion
            const privateInput = [
                number.toHex(number.toBN(config.STARK_PRIVATE_INPUT_1)),
                number.toHex(number.toBN(config.STARK_PRIVATE_INPUT_2))
            ];

            console.log("Public Input:", publicInput);
            console.log("Private Input:", privateInput);
            console.log("Generating STARK proof...");
            
            // Generate proof
            const proof = await this.starkContract.generate_stark_proof(
                publicInput,
                privateInput
            );

            console.log("Generated Proof:", proof);
            console.log("Verifying STARK proof...");
            
            // Verify proof
            const verificationResult = await this.starkContract.verify_stark_proof(
                publicInput,
                proof
            );

            console.log("Verification Result:", verificationResult);

            return {
                verified: verificationResult,
                proof: proof,
                publicInput: publicInput
            };

        } catch (error) {
            console.error("Detailed error in generateAndVerifyProof:", error);
            throw new Error(`Failed to generate or verify STARK proof: ${error.message}`);
        }
    }

    async generateSignature(messageHash) {
        // Generate a placeholder signature that's compatible with your contract
        return messageHash.toString();
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
