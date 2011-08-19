package org.springframework.security.oauth2.provider.refresh;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.util.Assert;

/**
 * Authentication provider for granting access tokens using a refresh token.
 * 
 * @author Ryan Heaton
 */
public class RefreshAuthenticationProvider implements AuthenticationProvider, InitializingBean {

  private AuthenticationManager authenticationManager;

  public void afterPropertiesSet() throws Exception {
    Assert.notNull(this.authenticationManager, "An authentication manager must be provided.");
  }

  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    RefreshAuthenticationToken auth = (RefreshAuthenticationToken) authentication;
    Authentication clientAuth = getAuthenticationManager().authenticate(auth.getClientAuthentication());
    if (!(clientAuth instanceof AbstractAuthenticationToken)) {
      throw new IllegalStateException("Client authentication must be an AbstractAuthenticationToken in order to support the refresh token.");
    }
    ((AbstractAuthenticationToken)clientAuth).setDetails(new RefreshTokenDetails(auth.getRefreshToken()));
    return new OAuth2Authentication<Authentication, Authentication>(clientAuth, null);
  }

  public boolean supports(Class<?> authentication) {
    return RefreshAuthenticationToken.class.isAssignableFrom(authentication);
  }

  public AuthenticationManager getAuthenticationManager() {
    return authenticationManager;
  }

  @Autowired
  public void setAuthenticationManager(AuthenticationManager authenticationManager) {
    this.authenticationManager = authenticationManager;
  }

}
