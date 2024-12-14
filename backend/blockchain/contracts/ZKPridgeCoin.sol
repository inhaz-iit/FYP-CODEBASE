// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract ZKPridgeCoin is ERC20, Ownable {
    constructor() ERC20("ZKPCoin", "ZKP") Ownable(msg.sender) {
        _mint(msg.sender, 10000 * 1e18); // Mint 10,000 tokens to the deployer
    }

    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }
}