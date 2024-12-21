const hre = require("hardhat");

async function main() {
    // Replace with your deployed contract address
    const contractAddress = "0x55D1E12F25E4a974E8a437d1BDD29b3535BCB0E5";

    // Attach to the deployed contract
    const Token = await hre.ethers.getContractAt("ZKPridgeCoin", contractAddress);

    // Call the owner() function
    const owner = await Token.owner();
    console.log(`Owner Address: ${owner}`);
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error("Error:", error);
        process.exit(1);
    });