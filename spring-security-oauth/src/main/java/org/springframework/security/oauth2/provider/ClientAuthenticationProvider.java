package org.springframework.security.oauth2.provider;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.exceptions.ClientAuthenticationException;
import org.springframework.util.Assert;

import java.util.List;
import java.util.Set;

/**
 * @author Ryan Heaton
 */
public class ClientAuthenticationProvider implements AuthenticationProvider, InitializingBean {

  private ClientDetailsService clientDetailsService;

  public void afterPropertiesSet() throws Exception {
    Assert.notNull(this.clientDetailsService, "Consumer details must be supplied");
  }

  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    ClientAuthenticationToken clientAuth = (ClientAuthenticationToken) authentication;
    ClientDetails clientDetails = getClientDetailsService().loadClientByClientId(clientAuth.getClientId());

    if (clientDetails.isSecretRequired()) {
      String assertedSecret = clientAuth.getClientSecret();
      if (assertedSecret == null) {
        throw new ClientAuthenticationException("Client secret is required but not provided.");
      }
      else {
        if (!assertedSecret.equals(clientDetails.getClientSecret())) {
          throw new ClientAuthenticationException("Invalid client secret.");
        }
      }
    }

    if (clientDetails.isScoped()) {
      Set<String> requestedScope = clientAuth.getScope();
      List<String> validScope = clientDetails.getScope();
      for (String scope : requestedScope) {
        if (!validScope.contains(scope)) {
          throw new ClientAuthenticationException("Unauthorized scope: " + scope);
        }
      }
    }

    List<String> authorizedFlows = clientDetails.getAuthorizedFlows();
    if (authorizedFlows != null && !authorizedFlows.contains(clientAuth.getFlowType())) {
      throw new ClientAuthenticationException("Unauthorized flow: " + clientAuth.getFlowType());
    }

    return new ClientAuthenticationToken(clientAuth, clientDetails.getAuthorities());
  }

  public boolean supports(Class<?> authentication) {
    return ClientAuthenticationToken.class.isAssignableFrom(authentication);
  }

  public ClientDetailsService getClientDetailsService() {
    return clientDetailsService;
  }

  @Autowired
  public void setClientDetailsService(ClientDetailsService clientDetailsService) {
    this.clientDetailsService = clientDetailsService;
  }
}
