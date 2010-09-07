package org.springframework.security.oauth2.consumer;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.DefaultOAuth2SerializationService;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2SerializationService;
import org.springframework.security.oauth2.consumer.token.InMemoryOAuth2ClientTokenServices;
import org.springframework.security.oauth2.consumer.token.OAuth2ClientTokenServices;
import org.springframework.util.Assert;

/**
 * @author Ryan Heaton
 */
public abstract class AbstractOAuth2FlowManager implements OAuth2FlowManager, InitializingBean {

  private OAuth2ClientTokenServices tokenServices = new InMemoryOAuth2ClientTokenServices();
  private OAuth2SerializationService serializationService = new DefaultOAuth2SerializationService();
  private boolean requireAuthenticated = true;

  public void afterPropertiesSet() throws Exception {
    Assert.notNull(tokenServices, "OAuth2 token services is required.");
    Assert.notNull(serializationService, "OAuth2 serialization service is required.");
  }

  public OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails resource) throws UserRedirectRequiredException, AccessDeniedException {
    OAuth2AccessToken accessToken = null;
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    if (isRequireAuthenticated() && (auth == null || !auth.isAuthenticated())) {
      throw new OAuth2AccessDeniedException("An authenticated context is required for the current user in order to obtain an access token.", resource);
    }
    final OAuth2AccessToken existingToken = getTokenServices().getToken(auth, resource);
    if (existingToken != null) {
      if (isExpired(existingToken)) {
        OAuth2RefreshToken refreshToken = existingToken.getRefreshToken();
        if (refreshToken != null) {
          accessToken = obtainAccessToken(resource, refreshToken);
        }
      }
      else {
        accessToken = existingToken;
      }
    }

    if (accessToken == null) {
      //looks like we need to try to obtain a new token.
      accessToken = obtainNewAccessToken(resource);

      if (accessToken == null) {
        throw new IllegalStateException("An OAuth 2 access token must be obtained or an exception thrown.");
      }
    }

    //store the token as needed.
    if (!accessToken.equals(existingToken)) {
      if (existingToken == null) {
        getTokenServices().storeToken(auth, resource, accessToken);
      }
      else {
        getTokenServices().updateToken(auth, resource, existingToken, accessToken);
      }
    }

    return accessToken;
  }

  /**
   * Obtain a new access token for the specified resource.
   *
   * @param details The resource.
   * @return The access token. May not be null.
   */
  protected abstract OAuth2AccessToken obtainNewAccessToken(OAuth2ProtectedResourceDetails details) throws UserRedirectRequiredException, AccessDeniedException;

  /**
   * Obtain a new access token for the specified resource using the refresh token.
   *
   * @param details The resource.
   * @param refreshToken The refresh token.
   * @return The access token, or null if failed.
   */
  protected OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails details, OAuth2RefreshToken refreshToken) {
    //todo: implement obtaining the refresh token. 
    return null;
  }

  /**
   * Whether the specified access token is expired.
   *
   * @param token The token.
   * @return Whether the specified access token is expired.
   */
  protected boolean isExpired(OAuth2AccessToken token) {
    return token.getExpiration() == null || token.getExpiration().getTime() < System.currentTimeMillis();
  }

  public OAuth2ClientTokenServices getTokenServices() {
    return tokenServices;
  }

  public void setTokenServices(OAuth2ClientTokenServices tokenServices) {
    this.tokenServices = tokenServices;
  }

  public OAuth2SerializationService getSerializationService() {
    return serializationService;
  }

  public void setSerializationService(OAuth2SerializationService serializationService) {
    this.serializationService = serializationService;
  }

  public boolean isRequireAuthenticated() {
    return requireAuthenticated;
  }

  public void setRequireAuthenticated(boolean requireAuthenticated) {
    this.requireAuthenticated = requireAuthenticated;
  }
}
