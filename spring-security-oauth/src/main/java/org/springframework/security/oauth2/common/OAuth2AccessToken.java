package org.springframework.security.oauth2.common;

import java.io.Serializable;
import java.util.Date;
import java.util.Set;

/**
 * Basic access token for OAuth 2.
 *
 * @author Ryan Heaton
 */
public class OAuth2AccessToken implements Serializable {

  private String value;
  private Date expiration;
  private String secret;
  private OAuth2RefreshToken refreshToken;
  private Set<String> scope;

  /**
   * The token value.
   *
   * @return The token value.
   */
  public String getValue() {
    return value;
  }

  /**
   * The token value.
   *
   * @param value The token value.
   */
  public void setValue(String value) {
    this.value = value;
  }

  /**
   * The instant the token expires.
   *
   * @return The instant the token expires.
   */
  public Date getExpiration() {
    return expiration;
  }

  /**
   * The instant the token expires.
   *
   * @param expiration The instant the token expires.
   */
  public void setExpiration(Date expiration) {
    this.expiration = expiration;
  }

  /**
   * The access token secret, if any.
   *
   * @return The access token secret, if any.
   */
  public String getSecret() {
    return secret;
  }

  /**
   * The access token secret, if any.
   *
   * @param secret The access token secret, if any.
   */
  public void setSecret(String secret) {
    this.secret = secret;
  }

  /**
   * The refresh token associated with the access token, if any.
   *
   * @return The refresh token associated with the access token, if any.
   */
  public OAuth2RefreshToken getRefreshToken() {
    return refreshToken;
  }

  /**
   * The refresh token associated with the access token, if any.
   *
   * @param refreshToken The refresh token associated with the access token, if any.
   */
  public void setRefreshToken(OAuth2RefreshToken refreshToken) {
    this.refreshToken = refreshToken;
  }

  /**
   * The scope of the token.
   *
   * @return The scope of the token.
   */
  public Set<String> getScope() {
    return scope;
  }

  /**
   * The scope of the token.
   *
   * @param scope The scope of the token.
   */
  public void setScope(Set<String> scope) {
    this.scope = scope;
  }

  @Override
  public boolean equals(Object obj) {
    return obj != null && toString().equals(obj.toString());
  }

  @Override
  public int hashCode() {
    return toString().hashCode();
  }

  @Override
  public String toString() {
    return getValue();
  }
}
