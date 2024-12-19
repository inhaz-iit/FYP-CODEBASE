// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

import "./WrappedZKPridgeCoin.sol";

contract MintContract is Ownable {
    // Reference to the token contract
    WrappedZKPridgeCoin public token;

    // Event emitted when tokens are minted
    event TokensMinted(address indexed to, uint256 amount);

    constructor(address _tokenAddress) Ownable(msg.sender) {
        require(_tokenAddress != address(0), "Invalid token address");
        token = WrappedZKPridgeCoin(_tokenAddress);
    }

    function mintTokens(address to, uint256 amount) external onlyOwner {
        require(to != address(0), "Invalid address"); // Ensure recipient address is not zero
        require(amount > 0, "Invalid amount"); // Ensure amount is greater than zero

        // Call the `mint` function on the token contract
        token.mint(to, amount);

        // Emit an event to log the minting action
        emit TokensMinted(to, amount);
    }
}
