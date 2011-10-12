package org.springframework.security.oauth2.client.provider;

import java.util.Collections;
import java.util.List;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.client.OAuth2AccessTokenProvider;
import org.springframework.security.oauth2.client.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.http.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;

/**
 * A chain of OAuth2 access token providers. This implementation will iterate through its chain to find the first provider
 * that supports the resource and use it to obtain the access token. Note, then, that the order of the chain is relevant.
 *
 * @author Ryan Heaton
 */
public class OAuth2AccessTokenProviderChain extends AbstractOAuth2AccessTokenManager {

  private final List<OAuth2AccessTokenProvider> chain;

  public OAuth2AccessTokenProviderChain(List<OAuth2AccessTokenProvider> chain) {
    this.chain = chain == null ? Collections.<OAuth2AccessTokenProvider>emptyList() : Collections.unmodifiableList(chain);
  }

  @Override
  protected OAuth2AccessToken obtainNewAccessToken(OAuth2ProtectedResourceDetails details) throws UserRedirectRequiredException, AccessDeniedException {
    for (OAuth2AccessTokenProvider tokenProvider : chain) {
      if (tokenProvider.supportsResource(details)) {
        return tokenProvider.obtainNewAccessToken(details);
      }
    }

    throw new OAuth2AccessDeniedException("Unable to obtain a new access token for resource '" + details.getId() + "'. The provider manager is not configured to support it.", details);
  }

  /**
   * The chain.
   *
   * @return The chain.
   */
  public List<OAuth2AccessTokenProvider> getChain() {
    return chain;
  }

}
