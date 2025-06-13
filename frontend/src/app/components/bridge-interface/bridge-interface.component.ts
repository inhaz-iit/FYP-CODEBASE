import { Component, OnInit } from '@angular/core';
import { MetaMaskService } from '../../services/meta-mask.service';
import { TokenService } from '../../services/token.service';

@Component({
  selector: 'app-bridge-interface',
  templateUrl: './bridge-interface.component.html',
  styleUrls: ['./bridge-interface.component.css']
})
export class BridgeInterfaceComponent implements OnInit {
  
  title = 'zkpridge-bridge';
  walletConnected = false;
  currentNetwork = 'Ethereum Sepolia Testnet';
  targetNetwork = 'Polygon Amoy Testnet';
  amount = '0';
  sourceWalletAddress = '0x0000...0000';
  targetWalletAddress = '0x0000...0000';
  
  // New properties
  tokenSymbol = 'ZKP';
  tokenBalance = '0';
  isLoading = false;
  transactionHash = '';
  errorMessage = '';
  
  networks = [
    { name: 'Ethereum Sepolia Testnet', icon: '🔵' },
    { name: 'Polygon Amoy Testnet', icon: '🟣' },
  ];
  
  constructor(
    private metamaskService: MetaMaskService,
    private tokenService: TokenService
  ) { }
  
  async connectWallet() {
    try {
      this.isLoading = true;
      this.errorMessage = '';
      
      // Use the actual MetaMask service to connect
      const account = await this.metamaskService.connect();
      this.walletConnected = true;
      this.sourceWalletAddress = account;
      this.targetWalletAddress = account; // Default to same address, user can change
      
      // Get token balance and symbol
      await this.updateTokenInfo();
      
    } catch (error: any) {
      console.error('Failed to connect wallet:', error);
      this.errorMessage = error.message || 'Failed to connect wallet';
      alert('Failed to connect to MetaMask. Please make sure it is installed and unlocked.');
    } finally {
      this.isLoading = false;
    }
  }

  async updateTokenInfo() {
    try {
      if (this.walletConnected) {
        // Get token symbol
        this.tokenSymbol = await this.tokenService.getTokenSymbol();
        
        // Get token balance
        this.tokenBalance = await this.tokenService.getTokenBalance(this.sourceWalletAddress);
      }
    } catch (error: any) {
      console.error('Error updating token info:', error);
      this.errorMessage = error.message || 'Error updating token info';
    }
  }

  setNetwork(type: 'current' | 'target', network: string) {
    if (type === 'current') {
      this.currentNetwork = network;
      // Optionally switch the network in MetaMask as well
      const chainId = this.metamaskService.getChainIdByName(network);
      if (chainId) {
        this.metamaskService.switchNetwork(chainId).catch(error => {
          console.error('Failed to switch network:', error);
        });
      }
    } else {
      this.targetNetwork = network;
    }
  }

  setMaxAmount() {
    if (this.tokenBalance) {
      this.amount = this.tokenBalance;
    }
  }

  async send() {
    // This initiates the bridge transaction
    if (!this.walletConnected) {
      alert('Please connect your wallet first');
      return;
    }
    
    // Validate amount
    if (!this.amount || parseFloat(this.amount) <= 0) {
      alert('Please enter a valid amount');
      return;
    }
    
    // Validate target address
    if (!this.targetWalletAddress || this.targetWalletAddress.length < 42) {
      alert('Please enter a valid target wallet address');
      return;
    }
    
    try {
      this.isLoading = true;
      this.errorMessage = '';
      this.transactionHash = '';
      
      // Check if lock contract has allowance to spend tokens
      const hasAllowance = await this.tokenService.checkAllowance(this.sourceWalletAddress);
      
      // If no allowance, approve tokens first
      if (!hasAllowance) {
        console.log('Approving tokens...');
        const approvalTxHash = await this.tokenService.approveTokens(this.amount);
        console.log('Tokens approved. Transaction hash:', approvalTxHash);
      }
      
      // Now lock the tokens
      console.log('Locking tokens...');
      this.transactionHash = await this.tokenService.lockTokens(
        this.amount,
        this.targetWalletAddress
      );
      
      console.log('Tokens locked. Transaction hash:', this.transactionHash);
      alert(`Tokens successfully locked! Transaction hash: ${this.transactionHash}`);
      
      // Reset amount
      this.amount = '0';
      
      // Update token balance
      await this.updateTokenInfo();
      
    } catch (error: any) {
      console.error('Error sending tokens:', error);
      this.errorMessage = error.message || 'Error sending tokens';
      alert(`Failed to lock tokens: ${this.errorMessage}`);
    } finally {
      this.isLoading = false;
    }
  }

  ngOnInit(): void {
    // Subscribe to account changes
    this.metamaskService.isConnected$.subscribe(isConnected => {
      this.walletConnected = isConnected;
      
      // Update token info when connection status changes
      if (isConnected) {
        this.updateTokenInfo();
      }
    });
    
    this.metamaskService.account$.subscribe(account => {
      if (account) {
        this.sourceWalletAddress = account;
        
        // Update token info when account changes
        this.updateTokenInfo();
      }
    });
    
    this.metamaskService.chainName$.subscribe(chainName => {
      if (chainName && chainName !== 'Unknown Network') {
        this.currentNetwork = chainName;
      }
    });
    
    // Check if already connected
    this.metamaskService.checkConnection();
  }
}