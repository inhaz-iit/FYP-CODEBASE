import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';
import detectEthereumProvider from '@metamask/detect-provider';
import { ethers } from 'ethers';

@Injectable({
  providedIn: 'root'
})
export class MetaMaskService {
  private provider: any;
  private _isConnected = new BehaviorSubject<boolean>(false);
  private _account = new BehaviorSubject<string>('');
  private _chainId = new BehaviorSubject<string>('');
  private _chainName = new BehaviorSubject<string>('');

  // Observable streams
  isConnected$ = this._isConnected.asObservable();
  account$ = this._account.asObservable();
  chainId$ = this._chainId.asObservable();
  chainName$ = this._chainName.asObservable();

  // Chain mapping
  private chainIdMapping: { [key: string]: string } = {
    '0x1': 'Ethereum',
    '0x89': 'Polygon',
  };

  constructor() {
    this.initialize();
  }

  async initialize() {
    try {
      // Detect the MetaMask Ethereum provider
      this.provider = await detectEthereumProvider();
      
      if (this.provider) {
        // Subscribe to account changes
        this.provider.on('accountsChanged', (accounts: string[]) => {
          if (accounts.length === 0) {
            // User has disconnected
            this._isConnected.next(false);
            this._account.next('');
          } else {
            this._account.next(accounts[0]);
          }
        });

        // Subscribe to chain changes
        this.provider.on('chainChanged', (chainId: string) => {
          this._chainId.next(chainId);
          this._chainName.next(this.getChainName(chainId));
        });

        // Check if already connected
        this.checkConnection();
      } else {
        console.error('Please install MetaMask!');
      }
    } catch (error) {
      console.error('Error initializing MetaMask:', error);
    }
  }

  async checkConnection() {
    try {
      // Check if we're already connected
      const accounts = await this.provider.request({ method: 'eth_accounts' });
      if (accounts.length > 0) {
        this._isConnected.next(true);
        this._account.next(accounts[0]);
        
        // Get current chain
        const chainId = await this.provider.request({ method: 'eth_chainId' });
        this._chainId.next(chainId);
        this._chainName.next(this.getChainName(chainId));
      }
    } catch (error) {
      console.error('Error checking connection:', error);
    }
  }

  async connect(): Promise<string> {
    try {
      if (!this.provider) {
        throw new Error('MetaMask not installed');
      }
      
      // Request accounts permission
      const accounts = await this.provider.request({ method: 'eth_requestAccounts' });
      
      // Get current chain
      const chainId = await this.provider.request({ method: 'eth_chainId' });
      
      if (accounts.length > 0) {
        this._isConnected.next(true);
        this._account.next(accounts[0]);
        this._chainId.next(chainId);
        this._chainName.next(this.getChainName(chainId));
        return accounts[0];
      } else {
        throw new Error('No accounts found');
      }
    } catch (error) {
      console.error('Error connecting to MetaMask:', error);
      throw error;
    }
  }

  async disconnect() {
    // Note: MetaMask doesn't actually have a disconnect method
    // This just resets our local state
    this._isConnected.next(false);
    this._account.next('');
  }

  async switchNetwork(chainId: string): Promise<boolean> {
    try {
      if (!this.provider) {
        throw new Error('MetaMask not installed');
      }
      
      await this.provider.request({
        method: 'wallet_switchEthereumChain',
        params: [{ chainId }],
      });
      
      return true;
    } catch (error: any) {
      // This error code indicates that the chain has not been added to MetaMask
      if (error.code === 4902) {
        // You could add the chain here
        // This would require additional code to add networks
      }
      console.error('Error switching network:', error);
      throw error;
    }
  }

  getChainName(chainId: string): string {
    return this.chainIdMapping[chainId] || 'Unknown Network';
  }

  getChainIdByName(name: string): string | null {
    for (const [chainId, chainName] of Object.entries(this.chainIdMapping)) {
      if (chainName === name) {
        return chainId;
      }
    }
    return null;
  }

  async getBalance(address: string): Promise<string> {
    try {
      if (!this.provider) {
        throw new Error('MetaMask not installed');
      }
      
      const ethersProvider = new ethers.BrowserProvider(this.provider);
      const balance = await ethersProvider.getBalance(address);
      
      // Convert balance from wei to ether
      return ethers.formatEther(balance);
    } catch (error) {
      console.error('Error getting balance:', error);
      throw error;
    }
  }

  async sendTransaction(from: string, to: string, amount: string): Promise<string> {
    try {
      if (!this.provider) {
        throw new Error('MetaMask not installed');
      }
      
      const ethersProvider = new ethers.BrowserProvider(this.provider);
      const signer = await ethersProvider.getSigner();
      
      // Convert amount from ether to wei
      const value = ethers.parseEther(amount);
      
      const tx = await signer.sendTransaction({
        to,
        value
      });
      
      return tx.hash;
    } catch (error) {
      console.error('Error sending transaction:', error);
      throw error;
    }
  }
}