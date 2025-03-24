import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { UserService } from 'src/app/services/user.service';

@Component({
  selector: 'app-user-registration',
  templateUrl: './user-registration.component.html',
  styleUrls: ['./user-registration.component.css']
})
export class UserRegistrationComponent implements OnInit {
  signupForm: FormGroup;
  isSubmitting = false;
  errorMessage: string = '';
  successMessage: string = '';

  constructor(
    private userService: UserService,
    private fb: FormBuilder
  ) {
    this.signupForm = this.fb.group({
      name: ['', [Validators.required]],
      email: ['', [Validators.required, Validators.email]],
      phoneNumber: ['', [Validators.required]],
      password: ['', [Validators.required, Validators.minLength(8)]],
      confirmPassword: ['', Validators.required]
    });
  }

  onSubmit(): void {
    if (this.signupForm.invalid) {
      // Mark all fields as touched to trigger validation styling
      Object.keys(this.signupForm.controls).forEach(key => {
        const control = this.signupForm.get(key);
        control?.markAsTouched();
      });
      return;
    }

    this.isSubmitting = true;
    this.errorMessage = '';
    this.successMessage = '';

    const userData = this.signupForm.value;

    // Use the service layer to handle the registration
    this.userService.registerUser(userData).subscribe({
      next: (response: any) => {
        this.isSubmitting = false;
        this.successMessage = 'Account created successfully!';
        console.log(response);
        this.signupForm.reset();
      },
      error: (error) => {
        this.isSubmitting = false;
        this.errorMessage = error.error.message || 'Failed to create account. Please try again.';
        console.error('Registration error:', error);
      }
    });
  }

  // Helper methods to simplify template code
  hasError(controlName: string, errorName: string): boolean {
    const control = this.signupForm.get(controlName);
    return !!(control && control.touched && control.hasError(errorName));
  }

  get formControls() {
    return this.signupForm.controls;
  }

  get passwordMismatch(): boolean {
    return this.signupForm.get('password')?.value !== this.signupForm.get('confirmPassword')?.value;
  }

  ngOnInit(): void {
  }
}
