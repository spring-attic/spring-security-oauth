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

package org.springframework.security.oauth.provider.token;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.apache.commons.codec.binary.Base64;

import java.util.*;
import java.security.SecureRandom;

/**
 * Base implementation for token services that uses random values to generate tokens. Only the persistence mechanism
 * is left unimplemented.
 *
 * This base implementation creates tokens that have an expiration.  For request tokens, the default validity is
 * 10 minutes.  For access tokens, the default validity is 12 hours.
 *
 * @author Ryan Heaton
 */
public abstract class RandomValueProviderTokenServices implements OAuthProviderTokenServices, InitializingBean, OAuthTokenLifecycleRegistry {

  private Random random;
  private int requestTokenValiditySeconds = 60 * 10; //default 10 minutes.
  private int accessTokenValiditySeconds = 60 * 60 * 12; //default 12 hours.
  private int tokenSecretLengthBytes = 80;
  private final Collection<OAuthTokenLifecycleListener> lifecycleListeners = new HashSet<OAuthTokenLifecycleListener>();

  /**
   * Read a token from persistence.
   *
   * @param token The token to read.
   * @return The token, or null if the token doesn't exist.
   */
  protected abstract OAuthProviderTokenImpl readToken(String token);

  /**
   * Store a token from persistence.
   *
   * @param tokenValue The token value.
   * @param token The token to store.
   */
  protected abstract void storeToken(String tokenValue, OAuthProviderTokenImpl token);

  /**
   * Remove a token from persistence.
   *
   * @param tokenValue The token to remove.
   * @return The token that was removed.
   */
  protected abstract OAuthProviderTokenImpl removeToken(String tokenValue);

  /**
   * Initialze these token services. If no random generator is set, one will be created.
   *
   */
  public void afterPropertiesSet() throws Exception {
    if (random == null) {
      random = new SecureRandom();
    }
  }

  public OAuthProviderToken getToken(String token) throws AuthenticationException {
    OAuthProviderTokenImpl tokenImpl = readToken(token);

    if (tokenImpl == null) {
      throw new InvalidOAuthTokenException("Invalid token: " + token);
    }
    else if (isExpired(tokenImpl)) {
      removeToken(token);
      onTokenRemoved(tokenImpl);
      throw new ExpiredOAuthTokenException("Expired token.");
    }

    return tokenImpl;
  }

  /**
   * Whether the auth token is expired.
   *
   * @param authToken The auth token to check for expiration.
   * @return Whether the auth token is expired.
   */
  protected boolean isExpired(OAuthProviderTokenImpl authToken) {
    if (authToken.isAccessToken()) {
      if ((authToken.getTimestamp() + (getAccessTokenValiditySeconds() * 1000L)) < System.currentTimeMillis()) {
        return true;
      }
    }
    else {
      if ((authToken.getTimestamp() + (getRequestTokenValiditySeconds() * 1000L)) < System.currentTimeMillis()) {
        return true;
      }
    }

    return false;
  }

  public OAuthProviderToken createUnauthorizedRequestToken(String consumerKey, String callbackUrl) throws AuthenticationException {
    String tokenValue = UUID.randomUUID().toString();
    byte[] secretBytes = new byte[getTokenSecretLengthBytes()];
    getRandom().nextBytes(secretBytes);
    String secret = new String(Base64.encodeBase64(secretBytes));
    OAuthProviderTokenImpl token = new OAuthProviderTokenImpl();
    token.setAccessToken(false);
    token.setConsumerKey(consumerKey);
    token.setCallbackUrl(callbackUrl);
    token.setUserAuthentication(null);
    token.setSecret(secret);
    token.setValue(tokenValue);
    token.setTimestamp(System.currentTimeMillis());
    onTokenCreated(token);
    storeToken(tokenValue, token);
    return token;
  }

  public void authorizeRequestToken(String requestToken, String verifier, Authentication authentication) throws AuthenticationException {
    OAuthProviderTokenImpl tokenImpl = readToken(requestToken);

    if (tokenImpl == null) {
      throw new InvalidOAuthTokenException("Invalid token: " + requestToken);
    }
    else if (isExpired(tokenImpl)) {
      removeToken(requestToken);
      onTokenRemoved(tokenImpl);
      throw new ExpiredOAuthTokenException("Expired token.");
    }
    else if (tokenImpl.isAccessToken()) {
      throw new InvalidOAuthTokenException("Request to authorize an access token.");
    }

    tokenImpl.setUserAuthentication(authentication);
    tokenImpl.setTimestamp(System.currentTimeMillis());//reset the expiration.
    tokenImpl.setVerifier(verifier);
    storeToken(requestToken, tokenImpl);
  }

  public OAuthAccessProviderToken createAccessToken(String requestToken) throws AuthenticationException {
    OAuthProviderTokenImpl tokenImpl = readToken(requestToken);

    if (tokenImpl == null) {
      throw new InvalidOAuthTokenException("Invalid token: " + requestToken);
    }
    else if (isExpired(tokenImpl)) {
      removeToken(requestToken);
      onTokenRemoved(tokenImpl);
      throw new ExpiredOAuthTokenException("Expired token.");
    }
    else if (tokenImpl.isAccessToken()) {
      throw new InvalidOAuthTokenException("Not a request token.");
    }
    else if (tokenImpl.getUserAuthentication() == null) {
      throw new InvalidOAuthTokenException("Request token has not been authorized.");
    }

    OAuthProviderTokenImpl requestTokenImpl = removeToken(requestToken);
    if (requestTokenImpl != null) {
      onTokenRemoved(requestTokenImpl);
    }

    String tokenValue = UUID.randomUUID().toString();
    byte[] secretBytes = new byte[getTokenSecretLengthBytes()];
    getRandom().nextBytes(secretBytes);
    String secret = new String(Base64.encodeBase64(secretBytes));
    OAuthProviderTokenImpl token = new OAuthProviderTokenImpl();
    token.setAccessToken(true);
    token.setConsumerKey(tokenImpl.getConsumerKey());
    token.setUserAuthentication(tokenImpl.getUserAuthentication());
    token.setSecret(secret);
    token.setValue(tokenValue);
    token.setTimestamp(System.currentTimeMillis());
    onTokenCreated(token);
    storeToken(tokenValue, token);
    return token;
  }

  /**
   * Logic for handling event firing of a removed token.
   *
   * @param token The token that was removed (possibly null).
   */
  protected void onTokenRemoved(OAuthProviderTokenImpl token) {
    for (OAuthTokenLifecycleListener listener : getLifecycleListeners()) {
      listener.tokenExpired(token);
    }
  }

  /**
   * Logic for handling event firing of a created token.
   *
   * @param token The token that was created.
   */
  protected void onTokenCreated(OAuthProviderTokenImpl token) {
    for (OAuthTokenLifecycleListener listener : getLifecycleListeners()) {
      listener.tokenCreated(token);
    }
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
  public int getRequestTokenValiditySeconds() {
    return requestTokenValiditySeconds;
  }

  /**
   * The validity (in seconds) of the unauthenticated request token.
   *
   * @param requestTokenValiditySeconds The validity (in seconds) of the unauthenticated request token.
   */
  public void setRequestTokenValiditySeconds(int requestTokenValiditySeconds) {
    this.requestTokenValiditySeconds = requestTokenValiditySeconds;
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
   * The collection of lifecycle listeners for these services.
   *
   * @return The collection of lifecycle listeners for these services.
   */
  public Collection<OAuthTokenLifecycleListener> getLifecycleListeners() {
    return lifecycleListeners;
  }

  /**
   * Register lifecycle listener(s) with these token services.
   *
   * @param lifecycleListeners The listeners.
   */
  @Autowired ( required = false )
  public void register(OAuthTokenLifecycleListener... lifecycleListeners) {
    if (lifecycleListeners != null) {
      this.lifecycleListeners.addAll(Arrays.asList(lifecycleListeners));
    }
  }
}
