// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract LockContract {
    IERC20 public token;

    event TokensLocked(address indexed user, uint256 amount, string destinationAddress);

    constructor(address _tokenAddress) {
        token = IERC20(_tokenAddress);
    }

    function lockTokens(uint256 amount, string memory destinationAddress) external {
        require(amount > 0, "Amount must be greater than zero");

        // Transfer tokens from the user to the contract
        token.transferFrom(msg.sender, address(this), amount);

        // Emit event for relayer to process
        emit TokensLocked(msg.sender, amount, destinationAddress);
    }

    // Optional: Withdraw locked tokens (for admin/emergency use)
    function withdrawLockedTokens(uint256 amount) external {
        token.transfer(msg.sender, amount);
    }
}