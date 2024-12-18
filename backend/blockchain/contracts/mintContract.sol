// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title MintContract
 * @dev A contract to mint tokens to specified addresses. Only the owner can mint tokens.
 */
contract MintContract is Ownable {
    // Interface for the ERC20 token contract
    IERC20 public token;

    // Event emitted when tokens are minted
    event TokensMinted(address indexed to, uint256 amount);

    /**
     * @dev Constructor to initialize the token contract address and set the contract owner.
     * @param _tokenAddress Address of the ERC20 token contract.
     */
    constructor(address _tokenAddress) Ownable(msg.sender) {
        require(_tokenAddress != address(0), "Invalid token address");
        token = IERC20(_tokenAddress); // Assign the token contract interface
    }

    /**
     * @dev Mint tokens to a specified address. Only callable by the owner.
     * @param to Address to which the tokens will be minted.
     * @param amount Number of tokens to mint.
     */
    function mintTokens(address to, uint256 amount) external onlyOwner {
        require(to != address(0), "Invalid address"); // Ensure recipient address is not zero
        require(amount > 0, "Invalid amount"); // Ensure amount is greater than zero
        
        // Call the `transfer` function on the token contract to send tokens
        bool success = token.transfer(to, amount);
        require(success, "Token minting failed"); // Verify the transfer was successful

        // Emit an event to log the minting action
        emit TokensMinted(to, amount);
    }
}