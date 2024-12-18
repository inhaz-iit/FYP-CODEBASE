const { ethers } = require("hardhat");
const config = require("../../configuration/config");

async function main() {
    const tokenAddress = config.WRAPPED_TOKEN_ADDRESS;
    const [deployer] = await ethers.getSigners();

    console.log("Deploying MintContract with account:", deployer.address);

    const MintContract = await ethers.getContractFactory("MintContract");
    const mintContract = await MintContract.deploy(tokenAddress);

    await mintContract.waitForDeployment();
    
    console.log("mintContract deployed to:", mintContract);
    console.log("MintContract deployed to:", await mintContract.getAddress());
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });