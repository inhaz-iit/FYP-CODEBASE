import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { UserRegistrationPageComponent } from './pages/user-registration-page/user-registration-page.component';

const routes: Routes = [
  {path: 'registration', component: UserRegistrationPageComponent},
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
