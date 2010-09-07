package org.springframework.security.oauth2.consumer;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.common.DefaultOAuth2SerializationService;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2SerializationService;
import org.springframework.security.oauth2.consumer.token.OAuth2ConsumerTokenServices;
import org.springframework.util.Assert;

/**
 * @author Ryan Heaton
 */
public abstract class AbstractOAuth2FlowManager implements OAuth2FlowManager, InitializingBean {

  private OAuth2ConsumerTokenServices tokenServices;
  private OAuth2SerializationService serializationService = new DefaultOAuth2SerializationService();

  public void afterPropertiesSet() throws Exception {
    Assert.notNull(tokenServices, "OAuth2 token services is required.");
    Assert.notNull(serializationService, "OAuth2 serialization service is required.");
  }

  public OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails resource) throws UserRedirectRequiredException, AccessDeniedException {
    OAuth2AccessToken accessToken = null;
    final OAuth2AccessToken existingToken = getTokenServices().getToken(resource);
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
    }

    //store the token if it exists.
    if (accessToken != null) {
      if (!accessToken.equals(existingToken)) {
        if (existingToken == null) {
          getTokenServices().storeToken(resource, accessToken);
        }
        else {
          getTokenServices().updateToken(resource, existingToken, accessToken);
        }
      }
    }

    return accessToken;
  }

  /**
   * Obtain a new access token for the specified resource.
   *
   * @param details The resource.
   * @return The access token.
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

  public OAuth2ConsumerTokenServices getTokenServices() {
    return tokenServices;
  }

  public void setTokenServices(OAuth2ConsumerTokenServices tokenServices) {
    this.tokenServices = tokenServices;
  }

  public OAuth2SerializationService getSerializationService() {
    return serializationService;
  }

  public void setSerializationService(OAuth2SerializationService serializationService) {
    this.serializationService = serializationService;
  }
}
