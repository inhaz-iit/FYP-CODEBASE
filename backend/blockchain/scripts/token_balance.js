const hre = require("hardhat");

async function main() {
    const contractAddress = "0x55D1E12F25E4a974E8a437d1BDD29b3535BCB0E5"; // Replace with your contract address
    const walletAddress = "0xbaCa1a7b55227FD1f25A1892df748E22282ca792"; // Replace with your wallet address

    // Attach to the deployed contract
    const Token = await hre.ethers.getContractAt("ZKPridgeCoin", contractAddress);

    // Check the balance of your wallet
    const balance = await Token.balanceOf(walletAddress);
    console.log(hre.ethers.formatUnits(balance,18));
    // console.log(`Token Balance: ${hre.ethers.utils.formatUnits() utils.formatUnits(balance, 18)} ZKP`);
    const balance2 = await Token.balanceOf("0xbaCa1a7b55227FD1f25A1892df748E22282ca792");
    console.log("Wallet => ",hre.ethers.formatUnits(balance2,18));
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error("Error:", error);
        process.exit(1);
    });