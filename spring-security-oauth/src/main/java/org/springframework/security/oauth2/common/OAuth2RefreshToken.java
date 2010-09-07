package org.springframework.security.oauth2.common;

import java.io.Serializable;

/**
 * An OAuth 2 refresh token.
 *
 * @author Ryan Heaton
 */
public class OAuth2RefreshToken implements Serializable {

  private String value;

  /**
   * The value of the token.
   *
   * @return The value of the token.
   */
  public String getValue() {
    return value;
  }

  /**
   * The value of the token.
   *
   * @param value The value of the token.
   */
  public void setValue(String value) {
    this.value = value;
  }

  @Override
  public String toString() {
    return getValue();
  }

  @Override
  public boolean equals(Object obj) {
    return toString().equals(obj);
  }

  @Override
  public int hashCode() {
    return toString().hashCode();
  }
}
