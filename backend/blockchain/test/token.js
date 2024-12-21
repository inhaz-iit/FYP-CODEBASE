const { expect } = require("chai");

describe("Token Deployment", function () {
    it("Should deploy the token contract successfully", async function () {
        const Token = await ethers.getContractFactory("ZKPridgeCoin");
        const token = await Token.deploy();
        await token.deployed();

        expect(await token.name()).to.equal("ZKPCoin");
    });
});