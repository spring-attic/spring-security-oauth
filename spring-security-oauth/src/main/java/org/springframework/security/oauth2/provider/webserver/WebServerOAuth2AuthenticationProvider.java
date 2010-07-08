package org.springframework.security.oauth2.provider.webserver;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.exceptions.ClientAuthenticationException;
import org.springframework.security.oauth2.common.exceptions.InvalidVerificationCodeException;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.provider.ClientAuthenticationToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.util.Assert;

/**
 * @author Ryan Heaton
 */
public class WebServerOAuth2AuthenticationProvider implements AuthenticationProvider, InitializingBean {

  private AuthenticationManager authenticationManager;
  private VerificationCodeServices verificationServices;

  public void afterPropertiesSet() throws Exception {
    Assert.notNull(this.authenticationManager, "An authentication manager must be provided.");
    Assert.notNull(verificationServices, "Verification code services must be supplied.");
  }

  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    WebServerOAuth2AuthenticationToken auth = (WebServerOAuth2AuthenticationToken) authentication;
    ClientAuthenticationToken clientRequest = auth.getClientAuthentication();
    String verificationCode = clientRequest.getVerificationCode();
    if (verificationCode == null) {
      throw new ClientAuthenticationException("A verification code must be supplied.");
    }

    OAuth2Authentication storedAuth = getVerificationServices().consumeVerificationCode(verificationCode);
    if (storedAuth == null) {
      throw new InvalidVerificationCodeException("Invalid verification code: " + verificationCode);
    }

    ClientAuthenticationToken storedClientAuth = (ClientAuthenticationToken) storedAuth.getClientAuthentication();
    if (storedClientAuth.getRequestedRedirect() != null && !storedClientAuth.getRequestedRedirect().equals(clientRequest.getRequestedRedirect())) {
      throw new RedirectMismatchException("Redirect URI mismatch.");
    }

    if (clientRequest.getClientId() == null || !clientRequest.getClientId().equals(storedClientAuth.getClientId())) {
      //just a sanity check.
      throw new ClientAuthenticationException("Client ID mismatch");
    }

    ClientAuthenticationToken combinedClientAuth = new ClientAuthenticationToken(clientRequest.getClientId(), clientRequest.getClientSecret(), storedClientAuth.getScope(), WebServerOAuth2AuthenticationToken.FLOW_TYPE);
    Authentication clientAuth = this.authenticationManager.authenticate(combinedClientAuth);
    Authentication userAuth = storedAuth.getUserAuthentication();
    return new OAuth2Authentication(clientAuth, userAuth);
  }

  public boolean supports(Class authentication) {
    return WebServerOAuth2AuthenticationToken.class.isAssignableFrom(authentication);
  }

  public AuthenticationManager getAuthenticationManager() {
    return authenticationManager;
  }

  @Autowired
  public void setAuthenticationManager(AuthenticationManager authenticationManager) {
    this.authenticationManager = authenticationManager;
  }

  public VerificationCodeServices getVerificationServices() {
    return verificationServices;
  }

  @Autowired
  public void setVerificationServices(VerificationCodeServices verificationServices) {
    this.verificationServices = verificationServices;
  }

}