const hre = require("hardhat");
const config = require("../../configuration/config"); // Update with your config file path

async function main() {
    // Deployed contract addresses
    const wrappedTokenAddress = config.WRAPPED_TOKEN_ADDRESS; // Replace with actual WrappedZKPCoin address
    const mintContractAddress = config.MINT_CONTRACT_ADDRESS; // Replace with actual MintContract address

    // ABI for WrappedZKPCoin
    const wrappedTokenABI = require("../ABI/WrappedZKPridgeCoinABI"); // Replace with actual ABI file path

    // Initialize signer and contract instance
    const provider = new hre.ethers.JsonRpcProvider(config.AMOY_RPC);
    const signer = new hre.ethers.Wallet(config.PRIVATE_KEY, provider);
    const wrappedToken = new hre.ethers.Contract(wrappedTokenAddress, wrappedTokenABI, signer);

    console.log(`Authorizing MintContract (${mintContractAddress}) as minter for WrappedZKPCoin...`);

    try {
        // Call the `setMinter` function
        const tx = await wrappedToken.setMinter(mintContractAddress);
        await tx.wait();

        console.log("MintContract successfully authorized as minter!");
    } catch (error) {
        console.error("Error authorizing minter:", error);
    }
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error("Error:", error);
        process.exit(1);
    });