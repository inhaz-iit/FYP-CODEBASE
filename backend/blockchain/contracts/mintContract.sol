// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "./WrappedZKPridgeCoin.sol";

contract MintContract is Ownable {
    // Reference to the Wrapped Token Contract
    WrappedZKPridgeCoin public token;

    // Event emitted when tokens are minted
    event TokensMinted(address indexed to, uint256 amount);

    constructor(address _tokenAddress) Ownable(msg.sender) {
        require(_tokenAddress != address(0), "Invalid token address");
        token = WrappedZKPridgeCoin(_tokenAddress);
    }

    function mintTokens(address to, uint256 amount) external onlyOwner {
        token.mint(to, amount); // Call mint function on Wrapped Token Contract
         // Emit an event to log the minting action
        emit TokensMinted(to, amount);
    }
}