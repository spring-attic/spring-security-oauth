package org.springframework.security.oauth2.provider.token;

import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Implementation of token services that stores tokens in memory.
 *
 * @author Ryan Heaton
 */
public class InMemoryOAuth2ProviderTokenServices extends RandomValueOAuth2ProviderTokenServices {

  protected final ConcurrentHashMap<String, OAuth2AccessToken> accessTokenStore = new ConcurrentHashMap<String, OAuth2AccessToken>();
  protected final ConcurrentHashMap<String, ExpiringOAuth2RefreshToken> refreshTokenStore = new ConcurrentHashMap<String, ExpiringOAuth2RefreshToken>();
  protected final ConcurrentHashMap<String, OAuth2Authentication> authenticationStore = new ConcurrentHashMap<String, OAuth2Authentication>();

  @Override
  protected void storeAuthentication(String tokenValue, OAuth2Authentication authentication) {
    this.authenticationStore.put(tokenValue, authentication);
  }

  @Override
  protected OAuth2Authentication readAuthentication(String value) {
    return this.authenticationStore.get(value);
  }

  @Override
  protected void removeAuthentication(String token) {
    this.authenticationStore.remove(token);
  }

  @Override
  protected void storeAccessToken(String tokenValue, OAuth2AccessToken token) {
    this.accessTokenStore.put(tokenValue, token);
  }

  @Override
  protected OAuth2AccessToken readAccessToken(String tokenValue) {
    return this.accessTokenStore.get(tokenValue);
  }

  @Override
  protected void removeAccessToken(String tokenValue) {
    this.accessTokenStore.remove(tokenValue);
  }

  @Override
  protected void storeRefreshToken(String tokenValue, ExpiringOAuth2RefreshToken refreshToken) {
    this.refreshTokenStore.put(tokenValue, refreshToken);
  }

  @Override
  protected ExpiringOAuth2RefreshToken readRefreshToken(String token) {
    return this.refreshTokenStore.get(token);
  }

  @Override
  protected void removeRefreshToken(String token) {
    this.refreshTokenStore.remove(token);
  }
}
