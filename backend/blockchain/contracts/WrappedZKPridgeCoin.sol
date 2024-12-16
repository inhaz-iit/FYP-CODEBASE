// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract WrappedZKPridgeCoin is ERC20, Ownable {
    constructor() ERC20("Wrapped ZKP Coin", "WZKP") Ownable(msg.sender) {
        _mint(msg.sender, 10000 * 1e18); // Mint 10,000 tokens to the deployer
    }

    // Function to mint new tokens (called by the bridge)
    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }

    // Function to burn tokens (for redeeming back to Ethereum)
    function burn(address from, uint256 amount) external onlyOwner {
        _burn(from, amount);
    }
}