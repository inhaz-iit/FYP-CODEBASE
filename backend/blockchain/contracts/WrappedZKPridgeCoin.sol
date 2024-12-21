// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract WrappedZKPridgeCoin is ERC20, Ownable {
    // Address of the authorized minter contract
    address public minter;

    constructor() ERC20("Wrapped ZKP Coin", "WZKP") Ownable(msg.sender) {
        _mint(msg.sender, 10000 * 1e18); // Mint initial supply
    }

    function setMinter(address _minter) external onlyOwner {
        require(_minter != address(0), "Invalid minter address");
        minter = _minter;
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == minter, "Caller is not the authorized minter");
        require(to != address(0), "Invalid recipient address");
        require(amount > 0, "Invalid amount");

        _mint(to, amount);
    }
}