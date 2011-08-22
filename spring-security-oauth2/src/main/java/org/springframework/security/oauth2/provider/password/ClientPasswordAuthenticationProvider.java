package org.springframework.security.oauth2.provider.password;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.provider.ClientAuthenticationToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.util.Assert;

/**
 * Authentication provider for granting access tokens using resource-owner password credentials.
 * 
 * @author Ryan Heaton
 */
public class ClientPasswordAuthenticationProvider implements AuthenticationProvider, InitializingBean {

  private AuthenticationManager authenticationManager;

  public void afterPropertiesSet() throws Exception {
    Assert.notNull(this.authenticationManager, "An authentication manager must be provided.");
  }

  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    ClientPasswordAuthenticationToken auth = (ClientPasswordAuthenticationToken) authentication;
    ClientAuthenticationToken clientAuth = (ClientAuthenticationToken) getAuthenticationManager().authenticate(auth.getClientAuthentication());
    Authentication userAuth;
    try {
      userAuth = getAuthenticationManager().authenticate(auth.getUserAuthentication());
    }
    catch (BadCredentialsException e) {
      throw new InvalidClientException("Invalid user credentials.", e);
    }
    return new OAuth2Authentication(clientAuth, userAuth);
  }

  public boolean supports(Class<?> authentication) {
    return ClientPasswordAuthenticationToken.class.isAssignableFrom(authentication);
  }

  public AuthenticationManager getAuthenticationManager() {
    return authenticationManager;
  }

  @Autowired
  public void setAuthenticationManager(AuthenticationManager authenticationManager) {
    this.authenticationManager = authenticationManager;
  }
}
