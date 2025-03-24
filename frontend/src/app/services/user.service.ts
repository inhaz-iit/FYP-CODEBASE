import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';

@Injectable({
  providedIn: 'root'
})
export class UserService {
  private baseUrl = 'http://localhost:5001/';

  constructor(private http: HttpClient) {}

  registerUser(userData: any) {
    return this.http.post(`${this.baseUrl}user/register`, userData);
  }
  
  loginUser(userData: any) {
    return this.http.post(`${this.baseUrl}user/login`, userData);
  }
}
