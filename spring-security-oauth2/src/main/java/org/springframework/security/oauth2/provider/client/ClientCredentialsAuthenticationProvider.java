package org.springframework.security.oauth2.provider.client;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.util.Assert;

public class ClientCredentialsAuthenticationProvider implements AuthenticationProvider, InitializingBean {

	  private AuthenticationManager authenticationManager;

	  public void afterPropertiesSet() throws Exception {
	    Assert.notNull(this.authenticationManager, "An authentication manager must be provided.");
	  }

	  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
	    ClientCredentialsAuthenticationToken auth = (ClientCredentialsAuthenticationToken) authentication;
	    Authentication clientAuth = getAuthenticationManager().authenticate(auth.getClientAuthentication());
	    return new OAuth2Authentication(clientAuth, null);
	  }

	  public boolean supports(Class<?> authentication) {
	    return ClientCredentialsAuthenticationToken.class.isAssignableFrom(authentication);
	  }

	  public AuthenticationManager getAuthenticationManager() {
	    return authenticationManager;
	  }

	  @Autowired
	  public void setAuthenticationManager(AuthenticationManager authenticationManager) {
	    this.authenticationManager = authenticationManager;
	  }
	

}
