import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { UserRegistrationPageComponent } from './pages/user-registration-page/user-registration-page.component';
import { LoginPageComponent } from './pages/login-page/login-page.component';
import { BridgePageComponent } from './pages/bridge-page/bridge-page.component';

const routes: Routes = [
  {path: 'registration', component: UserRegistrationPageComponent},
  {path: 'login', component: LoginPageComponent},
  {path: 'zkpridge', component: BridgePageComponent},
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
