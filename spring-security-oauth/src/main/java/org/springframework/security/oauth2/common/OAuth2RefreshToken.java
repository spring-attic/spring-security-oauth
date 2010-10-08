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
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof OAuth2RefreshToken)) {
      return false;
    }

    OAuth2RefreshToken that = (OAuth2RefreshToken) o;

    if (value != null ? !value.equals(that.value) : that.value != null) {
      return false;
    }

    return true;
  }

  @Override
  public int hashCode() {
    return value != null ? value.hashCode() : 0;
  }
}
