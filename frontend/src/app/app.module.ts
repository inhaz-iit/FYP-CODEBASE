import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
// import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { UserRegistrationComponent } from './components/user-registration/user-registration.component';
import { UserRegistrationPageComponent } from './pages/user-registration-page/user-registration-page.component';
import { ReactiveFormsModule } from '@angular/forms';
import { HttpClientModule } from '@angular/common/http';
import { LoginPageComponent } from './pages/login-page/login-page.component';
import { LoginComponent } from './components/login/login.component';
import { BridgePageComponent } from './pages/bridge-page/bridge-page.component';
import { BridgeInterfaceComponent } from './components/bridge-interface/bridge-interface.component';
import { MetaMaskService } from './services/meta-mask.service';
import { TokenService } from './services/token.service';

@NgModule({
  declarations: [
    AppComponent,
    UserRegistrationPageComponent,
    LoginPageComponent,
    BridgePageComponent,
    UserRegistrationComponent,
    LoginComponent,
    BridgeInterfaceComponent,
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    ReactiveFormsModule,
    HttpClientModule,
    FormsModule
  ],
  providers: [
    MetaMaskService,
    TokenService
  ],
  
  bootstrap: [AppComponent]
})
export class AppModule { }
