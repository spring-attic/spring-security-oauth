package org.springframework.security.oauth2.provider.verification;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.exceptions.*;
import org.springframework.security.oauth2.provider.AccessGrantAuthenticationToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.util.Assert;

import java.util.Set;

/**
 * Authentication provider that supplies an auth token in exchange for an authorization code.
 *
 * @author Ryan Heaton
 */
public class VerificationCodeAuthenticationProvider implements AuthenticationProvider, InitializingBean {

  private AuthenticationManager authenticationManager;
  private VerificationCodeServices verificationServices;

  public void afterPropertiesSet() throws Exception {
    Assert.notNull(this.authenticationManager, "An authentication manager must be provided.");
    Assert.notNull(this.verificationServices, "Verification code services must be supplied.");
  }

  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    AuthorizationCodeAuthenticationToken auth = (AuthorizationCodeAuthenticationToken) authentication;
    String verificationCode = auth.getVerificationCode();
    if (verificationCode == null) {
      throw new OAuth2Exception("A verification code must be supplied.");
    }

    OAuth2Authentication<? extends VerificationCodeAuthenticationToken, ? extends Authentication> storedAuth = getVerificationServices().consumeVerificationCode(verificationCode);
    if (storedAuth == null) {
      throw new InvalidGrantException("Invalid verification code: " + verificationCode);
    }

    VerificationCodeAuthenticationToken verificationAuth = storedAuth.getClientAuthentication();
    if (verificationAuth.getRequestedRedirect() != null && !verificationAuth.getRequestedRedirect().equals(auth.getRequestedRedirect())) {
      throw new RedirectMismatchException("Redirect URI mismatch.");
    }

    if (auth.getClientId() == null || !auth.getClientId().equals(verificationAuth.getClientId())) {
      //just a sanity check.
      throw new InvalidClientException("Client ID mismatch");
    }

    Set<String> verificationScope = verificationAuth.getScope();
    Set<String> authScope = auth.getScope();
    if (!verificationScope.containsAll(authScope)) {
      throw new InvalidScopeException("Request for access token scope outside of verification code scope.");
    }

    AccessGrantAuthenticationToken verifiedAuth = new AccessGrantAuthenticationToken(auth.getClientId(), auth.getClientSecret(), authScope, "authorization_code");
    Authentication clientAuth = getAuthenticationManager().authenticate(verifiedAuth);
    Authentication userAuth = storedAuth.getUserAuthentication();
    return new OAuth2Authentication<Authentication, Authentication>(clientAuth, userAuth);
  }

  public boolean supports(Class authentication) {
    return AuthorizationCodeAuthenticationToken.class.isAssignableFrom(authentication);
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