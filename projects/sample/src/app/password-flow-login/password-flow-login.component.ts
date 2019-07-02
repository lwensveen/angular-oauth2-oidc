import { authPasswordFlowConfig } from '../auth-password-flow.config';
import { Component, OnInit } from '@angular/core';
import { OAuthService } from '../../../../lib/src/oauth-service';

@Component({
  selector: 'app-password-flow-login',
  templateUrl: './password-flow-login.component.html'
})
export class PasswordFlowLoginComponent implements OnInit {
  userName: string;
  password: string;
  loginFailed = false;
  userProfile: object;
  claims: any;

  constructor(private oauthService: OAuthService) {
    // Tweak config for password flow
    // This is just needed b/c this demo uses both,
    // implicit flow as well as password flow

    this.oauthService.configure(authPasswordFlowConfig);
    this.oauthService.loadDiscoveryDocument();
  }

  get access_token() {
    return this.oauthService.getAccessToken();
  }

  get access_token_expiration() {
    return this.oauthService.getAccessTokenExpiration();
  }

  get givenName() {
    this.claims = this.oauthService.getIdentityClaims();
    if (!this.claims) {
      return null;
    }
    return this.claims.given_name;
  }

  get familyName() {
    this.claims = this.oauthService.getIdentityClaims();
    if (!this.claims) {
      return null;
    }
    return this.claims.family_name;
  }

  ngOnInit() {
  }

  loadUserProfile(): void {
    this.oauthService.loadUserProfile().then(up => (this.userProfile = up));
  }

  loginWithPassword() {
    this.oauthService
      .fetchTokenUsingPasswordFlowAndLoadUserProfile(
        this.userName,
        this.password
      ).then(() => {
      console.error('successfully logged in');
      this.loginFailed = false;
    }).catch(err => {
      console.error('error logging in', err);
      this.loginFailed = true;
    });
  }

  logout() {
    this.oauthService.logOut(true);
  }
}
