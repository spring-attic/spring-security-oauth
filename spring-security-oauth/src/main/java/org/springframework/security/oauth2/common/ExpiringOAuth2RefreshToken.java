package org.springframework.security.oauth2.common;

import java.util.Date;

/**
 * @author Ryan Heaton
 */
public class ExpiringOAuth2RefreshToken extends OAuth2RefreshToken {

  private static final long serialVersionUID = 3449554332764129719L;

  private Date expiration;

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

}
