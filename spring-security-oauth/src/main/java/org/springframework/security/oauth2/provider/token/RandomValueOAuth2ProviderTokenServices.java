/*
 * Copyright 2008 Web Cohesion
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.provider.token;

import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.*;
import org.springframework.security.oauth2.common.exceptions.ExpiredTokenException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.ClientAuthenticationToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import java.security.SecureRandom;
import java.util.Date;
import java.util.Random;
import java.util.UUID;

/**
 * Base implementation for token services that uses random values to generate tokens. Only the persistence mechanism
 * is left unimplemented.<br/><br/>
 *
 * @author Ryan Heaton
 */
public abstract class RandomValueOAuth2ProviderTokenServices implements OAuth2ProviderTokenServices, InitializingBean {

  private Random random;
  private int refreshTokenValiditySeconds = 60 * 60 * 24 * 30; //default 30 days.
  private int accessTokenValiditySeconds = 60 * 60 * 12; //default 12 hours.
  private boolean supportRefreshToken = false;
  private boolean reuseRefreshToken = true;
  private boolean requireSecret = false;
  private int tokenSecretLengthBytes = 80;

  /**
   * Initialze these token services. If no random generator is set, one will be created.
   *
   * @throws Exception
   */
  public void afterPropertiesSet() throws Exception {
    if (random == null) {
      random = new SecureRandom();
    }
  }

  /**
   * Store an authentication in the database.
   *
   * @param tokenValue The token value under which to store the authentication.
   * @param authentication The authentication to store.
   */
  protected abstract void storeAuthentication(String tokenValue, OAuth2Authentication authentication);

  /**
   * Read the authentication stored under the specified token value.
   *
   * @param value The token value under which the authentication is stored.
   * @return The authentication, or null if none.
   */
  protected abstract OAuth2Authentication readAuthentication(String value);

  /**
   * Remove the specified authentication.
   *
   * @param token The token key under which the authentication is stored.
   */
  protected abstract void removeAuthentication(String token);

  /**
   * Store an access token.
   *
   * @param tokenValue The token value.
   * @param token The token to store.
   */
  protected abstract void storeAccessToken(String tokenValue, OAuth2AccessToken token);

  /**
   * Read an access token from the store.
   *
   * @param tokenValue The token value.
   * @return The access token to read.
   */
  protected abstract OAuth2AccessToken readAccessToken(String tokenValue);

  /**
   * Remove an access token from the database.
   *
   * @param tokenValue The token to remove from the database.
   */
  protected abstract void removeAccessToken(String tokenValue);

  /**
   * Store the specified refresh token in the database.
   *
   * @param tokenValue the token value.
   * @param refreshToken The refresh token to store.
   */
  protected abstract void storeRefreshToken(String tokenValue, ExpiringOAuth2RefreshToken refreshToken);

  /**
   * Read a refresh token from the store.
   *
   * @param token The token to read.
   * @return The token.
   */
  protected abstract ExpiringOAuth2RefreshToken readRefreshToken(String token);

  /**
   * Remove a refresh token from the database.
   *
   * @param token The token to remove from the database.
   */
  protected abstract void removeRefreshToken(String token);

  public OAuth2AccessToken createAccessToken(OAuth2Authentication authentication) throws AuthenticationException {
    ExpiringOAuth2RefreshToken refreshToken = null;
    if (isSupportRefreshToken()) {
      refreshToken = createRefreshToken(authentication);
    }

    return createAccessToken(authentication, refreshToken);
  }

  public OAuth2AccessToken refreshAccessToken(String refreshTokenValue) throws AuthenticationException {
    if (!isSupportRefreshToken()) {
      throw new InvalidTokenException("Invalid refresh token: " + refreshTokenValue);
    }

    ExpiringOAuth2RefreshToken refreshToken = readRefreshToken(refreshTokenValue);
    if (refreshToken == null) {
      throw new InvalidTokenException("Invalid refresh token: " + refreshTokenValue);
    }
    else {
      boolean isExpired = isExpired(refreshToken);
      if (isExpired || isReuseRefreshToken()) {
        removeRefreshToken(refreshTokenValue);
        removeAuthentication(refreshTokenValue);

        if (isExpired) {
          throw new ExpiredTokenException("Expired refresh token: " + refreshToken);
        }
      }
    }

    OAuth2Authentication authentication = readAuthentication(refreshToken.getValue());

    if (isReuseRefreshToken()) {
      refreshToken = createRefreshToken(authentication);
    }

    return createAccessToken(authentication, refreshToken);
  }

  protected boolean isExpired(ExpiringOAuth2RefreshToken refreshToken) {
    return refreshToken.getExpiration() != null && System.currentTimeMillis() > refreshToken.getExpiration().getTime();
  }

  private boolean isExpired(OAuth2AccessToken accessToken) {
    return accessToken.getExpiration() == null || System.currentTimeMillis() > accessToken.getExpiration().getTime();
  }

  public OAuth2Authentication loadAuthentication(String accessTokenValue) throws AuthenticationException {
    OAuth2AccessToken accessToken = readAccessToken(accessTokenValue);
    if (accessToken == null) {
      throw new InvalidTokenException("Invalid access token: " + accessTokenValue);
    }
    else if (isExpired(accessToken)) {
      removeAccessToken(accessTokenValue);
      throw new ExpiredTokenException("Expired access token: " + accessTokenValue);
    }

    return readAuthentication(accessTokenValue);
  }

  protected ExpiringOAuth2RefreshToken createRefreshToken(OAuth2Authentication authentication) {
    ExpiringOAuth2RefreshToken refreshToken;
    refreshToken = new ExpiringOAuth2RefreshToken();
    String refreshTokenValue = UUID.randomUUID().toString();
    refreshToken.setValue(refreshTokenValue);
    refreshToken.setExpiration(new Date(System.currentTimeMillis() + (getRefreshTokenValiditySeconds() * 1000)));
    storeRefreshToken(refreshTokenValue, refreshToken);
    storeAuthentication(refreshTokenValue, authentication);
    return refreshToken;
  }

  protected OAuth2AccessToken createAccessToken(OAuth2Authentication authentication, OAuth2RefreshToken refreshToken) {
    OAuth2AccessToken token = new OAuth2AccessToken();
    String tokenValue = UUID.randomUUID().toString();
    token.setValue(tokenValue);

    String secret = null;
    if (isRequireSecret()) {
      byte[] secretBytes = new byte[getTokenSecretLengthBytes()];
      getRandom().nextBytes(secretBytes);
      secret = new String(Base64.encodeBase64(secretBytes));
    }
    token.setSecret(secret);
    token.setExpiration(new Date(System.currentTimeMillis() + (getAccessTokenValiditySeconds() * 1000)));
    token.setRefreshToken(refreshToken);
    if (authentication.getClientAuthentication() instanceof ClientAuthenticationToken) {
      token.setScope(((ClientAuthenticationToken)authentication.getClientAuthentication()).getScope());
    }
    storeAccessToken(tokenValue, token);
    storeAuthentication(tokenValue, authentication);
    return token;
  }

  /**
   * The length of the token secret in bytes, before being base64-encoded.
   *
   * @return The length of the token secret in bytes.
   */
  public int getTokenSecretLengthBytes() {
    return tokenSecretLengthBytes;
  }

  /**
   * The length of the token secret in bytes, before being base64-encoded.
   *
   * @param tokenSecretLengthBytes The length of the token secret in bytes, before being base64-encoded.
   */
  public void setTokenSecretLengthBytes(int tokenSecretLengthBytes) {
    this.tokenSecretLengthBytes = tokenSecretLengthBytes;
  }

  /**
   * The random value generator used to create token secrets.
   *
   * @return The random value generator used to create token secrets.
   */
  public Random getRandom() {
    return random;
  }

  /**
   * The random value generator used to create token secrets.
   *
   * @param random The random value generator used to create token secrets.
   */
  public void setRandom(Random random) {
    this.random = random;
  }

  /**
   * The validity (in seconds) of the unauthenticated request token.
   *
   * @return The validity (in seconds) of the unauthenticated request token.
   */
  public int getRefreshTokenValiditySeconds() {
    return refreshTokenValiditySeconds;
  }

  /**
   * The validity (in seconds) of the unauthenticated request token.
   *
   * @param refreshTokenValiditySeconds The validity (in seconds) of the unauthenticated request token.
   */
  public void setRefreshTokenValiditySeconds(int refreshTokenValiditySeconds) {
    this.refreshTokenValiditySeconds = refreshTokenValiditySeconds;
  }

  /**
   * The validity (in seconds) of the access token.
   *
   * @return The validity (in seconds) of the access token.
   */
  public int getAccessTokenValiditySeconds() {
    return accessTokenValiditySeconds;
  }

  /**
   * The validity (in seconds) of the access token.
   *
   * @param accessTokenValiditySeconds The validity (in seconds) of the access token.
   */
  public void setAccessTokenValiditySeconds(int accessTokenValiditySeconds) {
    this.accessTokenValiditySeconds = accessTokenValiditySeconds;
  }

  /**
   * Whether to support the refresh token.
   *
   * @return Whether to support the refresh token.
   */
  public boolean isSupportRefreshToken() {
    return supportRefreshToken;
  }

  /**
   * Whether to support the refresh token.
   *
   * @param supportRefreshToken Whether to support the refresh token.
   */
  public void setSupportRefreshToken(boolean supportRefreshToken) {
    this.supportRefreshToken = supportRefreshToken;
  }

  /**
   * Whether to reuse refresh tokens (until expired).
   *
   * @return Whether to reuse refresh tokens (until expired).
   */
  public boolean isReuseRefreshToken() {
    return reuseRefreshToken;
  }

  /**
   * Whether to reuse refresh tokens (until expired).
   *
   * @param reuseRefreshToken Whether to reuse refresh tokens (until expired).
   */
  public void setReuseRefreshToken(boolean reuseRefreshToken) {
    this.reuseRefreshToken = reuseRefreshToken;
  }

  /**
   * Whether to require a secret with the access token.
   *
   * @return Whether to require a secret with the access token.
   */
  public boolean isRequireSecret() {
    return requireSecret;
  }

  /**
   * Whether to require a secret with the access token.
   *
   * @param requireSecret Whether to require a secret with the access token.
   */
  public void setRequireSecret(boolean requireSecret) {
    this.requireSecret = requireSecret;
  }
}