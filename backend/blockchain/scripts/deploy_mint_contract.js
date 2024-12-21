const { ethers } = require("hardhat");
const config = require("../../configuration/config");

async function main() {
    const wrappedTokenAddress = config.WRAPPED_TOKEN_ADDRESS; // Replace with actual address
    const MintContract = await ethers.getContractFactory("MintContract");
    const mintContract = await MintContract.deploy(wrappedTokenAddress);
    
    await mintContract.waitForDeployment();
    
    console.log("mintContract deployed to:", mintContract);
    console.log("MintContract deployed to:", await mintContract.getAddress());
}
    
main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});