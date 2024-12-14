const hre = require("hardhat");

async function main() {
    // Get the contract factory
    const Token = await hre.ethers.getContractFactory("ZKPridgeCoin");

    console.log("Deploying contract...");

    // Deploy the contract and wait for it to be mined
    const token = await Token.deploy();
    const receipt = await token.deploymentTransaction();

    console.log("Contract deployed successfully!");
    console.log(`Contract Address: ${token.target}`);
    console.log("Transaction Hash:", receipt.getTransaction());
}

// Run the script
main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error("Error during deployment:", error);
        process.exit(1);
    });