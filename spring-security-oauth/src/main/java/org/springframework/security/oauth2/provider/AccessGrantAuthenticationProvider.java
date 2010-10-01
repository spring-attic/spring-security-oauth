package org.springframework.security.oauth2.provider;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.util.Assert;

import java.util.List;
import java.util.Set;

/**
 * Authentication provider for grants for access to an auth token.
 *  
 * @author Ryan Heaton
 */
public class AccessGrantAuthenticationProvider implements AuthenticationProvider, InitializingBean {

  private ClientDetailsService clientDetailsService;

  public void afterPropertiesSet() throws Exception {
    Assert.notNull(this.clientDetailsService, "Client details service must be supplied");
  }

  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    AccessGrantAuthenticationToken clientAuth = (AccessGrantAuthenticationToken) authentication;
    ClientDetails clientDetails = getClientDetailsService().loadClientByClientId(clientAuth.getClientId());

    if (clientDetails.isSecretRequired()) {
      String assertedSecret = clientAuth.getClientSecret();
      if (assertedSecret == null) {
        throw new InvalidClientException("Client secret is required but not provided.");
      }
      else {
        if (!assertedSecret.equals(clientDetails.getClientSecret())) {
          throw new InvalidClientException("Invalid client secret.");
        }
      }
    }

    if (clientDetails.isScoped()) {
      Set<String> requestedScope = clientAuth.getScope();
      List<String> validScope = clientDetails.getScope();
      for (String scope : requestedScope) {
        if (!validScope.contains(scope)) {
          throw new InvalidScopeException("Invalid scope: " + scope);
        }
      }
    }

    List<String> authorizedGrantTypes = clientDetails.getAuthorizedGrantTypes();
    if (authorizedGrantTypes != null && !authorizedGrantTypes.contains(clientAuth.getGrantType())) {
      throw new InvalidGrantException("Unauthorized grant type: " + clientAuth.getGrantType());
    }

    return new AuthorizedClientAuthenticationToken(clientAuth.getClientId(), clientAuth.getClientSecret(), clientAuth.getScope(), clientDetails.getAuthorities());
  }

  public boolean supports(Class<?> authentication) {
    return AccessGrantAuthenticationToken.class.isAssignableFrom(authentication);
  }

  public ClientDetailsService getClientDetailsService() {
    return clientDetailsService;
  }

  @Autowired
  public void setClientDetailsService(ClientDetailsService clientDetailsService) {
    this.clientDetailsService = clientDetailsService;
  }
}
