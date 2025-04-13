import { Injectable } from '@angular/core';
import { ethers, Contract } from 'ethers';

// Type declaration for window.ethereum
declare global {
  interface Window {
    ethereum: any;
  }
}

// ERC20 ABI - just the functions we need
const ERC20_ABI = [
  "function balanceOf(address owner) view returns (uint256)",
  "function decimals() view returns (uint8)",
  "function symbol() view returns (string)",
  "function transfer(address to, uint amount) returns (bool)",
  "function approve(address spender, uint256 amount) returns (bool)",
  "function allowance(address owner, address spender) view returns (uint256)"
];

// Lock Contract ABI
const LOCK_CONTRACT_ABI = [
  "function lockTokens(uint256 amount, string memory destinationAddress) external",
  "event TokensLocked(address indexed user, uint256 amount, string destinationAddress)"
];


@Injectable({
  providedIn: 'root'
})
export class TokenService {
  private provider: ethers.BrowserProvider | null = null;
  private signer: ethers.Signer | null = null;

  // Contract addresses
  private readonly TOKEN_ADDRESS = '0x55D1E12F25E4a974E8a437d1BDD29b3535BCB0E5';
  private readonly LOCK_CONTRACT_ADDRESS = '0xe475fb6d1f0b3760cb0e741eaaBa5f939e024AaB';

  // Contract instances
  private tokenContract: ethers.Contract | null = null;
  private lockContract: ethers.Contract | null = null;

  constructor() { }

  /**
   * Initialize provider, signer and contracts
   */
  async initialize() {
    // Check if window.ethereum exists
    if (window.ethereum) {
      try {
        this.provider = new ethers.BrowserProvider(window.ethereum);
        this.signer = await this.provider.getSigner();
        
        // Initialize contracts
        this.tokenContract = new ethers.Contract(
          this.TOKEN_ADDRESS,
          ERC20_ABI,
          this.signer
        );
        
        this.lockContract = new ethers.Contract(
          this.LOCK_CONTRACT_ADDRESS,
          LOCK_CONTRACT_ABI,
          this.signer
        );
      } catch (error) {
        console.error('Error initializing contracts:', error);
        throw error;
      }
    } else {
      throw new Error('MetaMask not installed');
    }
  }

  /**
   * Get token balance for an address
   */
  async getTokenBalance(address: string): Promise<string> {
    if (!this.tokenContract) {
      await this.initialize();
    }
    
    try {
      if (!this.tokenContract) {
        throw new Error('Token contract not initialized');
      }
      
      // Use bracket notation to access methods
      const balance = await this.tokenContract['balanceOf'](address);
      const decimals = await this.tokenContract['decimals']();
      
      // Format with proper decimal places
      return ethers.formatUnits(balance, decimals);
    } catch (error) {
      console.error('Error getting token balance:', error);
      throw error;
    }
  }

  /**
   * Get token symbol
   */
  async getTokenSymbol(): Promise<string> {
    if (!this.tokenContract) {
      await this.initialize();
    }
    
    try {
      if (!this.tokenContract) {
        throw new Error('Token contract not initialized');
      }
      
      return await this.tokenContract['symbol']();
    } catch (error) {
      console.error('Error getting token symbol:', error);
      throw error;
    }
  }

  /**
   * Check if lock contract has enough allowance to spend tokens
   */
  async checkAllowance(ownerAddress: string): Promise<boolean> {
    if (!this.tokenContract) {
      await this.initialize();
    }
    
    try {
      if (!this.tokenContract) {
        throw new Error('Token contract not initialized');
      }
      
      const allowance = await this.tokenContract['allowance'](
        ownerAddress,
        this.LOCK_CONTRACT_ADDRESS
      );
      
      // If allowance is greater than 0, return true
      return allowance > BigInt(0);
    } catch (error) {
      console.error('Error checking allowance:', error);
      throw error;
    }
  }

  /**
   * Approve lock contract to spend tokens
   */
  async approveTokens(amount: string): Promise<string> {
    if (!this.tokenContract) {
      await this.initialize();
    }
    
    try {
      if (!this.tokenContract) {
        throw new Error('Token contract not initialized');
      }
      
      const decimals = await this.tokenContract['decimals']();
      const parsedAmount = ethers.parseUnits(amount, decimals);
      
      // Approve the lock contract to spend tokens
      const tx = await this.tokenContract['approve'](
        this.LOCK_CONTRACT_ADDRESS,
        parsedAmount
      );
      
      // Wait for transaction to be mined
      const receipt = await tx.wait();
      return receipt?.hash || '';
    } catch (error) {
      console.error('Error approving tokens:', error);
      throw error;
    }
  }

  /**
   * Lock tokens in the contract
   */
  async lockTokens(amount: string, destinationAddress: string): Promise<string> {
    if (!this.lockContract || !this.tokenContract) {
      await this.initialize();
    }
    
    try {
      if (!this.lockContract || !this.tokenContract) {
        throw new Error('Contracts not initialized');
      }
      
      const decimals = await this.tokenContract['decimals']();
      const parsedAmount = ethers.parseUnits(amount, decimals);
      
      // Lock tokens
      const tx = await this.lockContract['lockTokens'](parsedAmount, destinationAddress);
      
      // Wait for transaction to be mined
      const receipt = await tx.wait();
      return receipt?.hash || '';
    } catch (error) {
      console.error('Error locking tokens:', error);
      throw error;
    }
  }
  
  /**
   * Listen for TokensLocked events
   */
  listenForLockEvents(callback: (user: string, amount: bigint, destinationAddress: string) => void) {
    if (!this.lockContract) {
      this.initialize().then(() => {
        this.setupEventListener(callback);
      });
    } else {
      this.setupEventListener(callback);
    }
  }
  
  private setupEventListener(callback: (user: string, amount: bigint, destinationAddress: string) => void) {
    if (!this.lockContract) return;
    
    this.lockContract.on('TokensLocked', (user, amount, destinationAddress) => {
      callback(user, amount, destinationAddress);
    });
  }
}