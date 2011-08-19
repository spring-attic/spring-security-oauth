package org.springframework.security.oauth2.provider.refresh;

/**
 * Holder for refresh token details.
 *
 * @author Ryan Heaton
 */
public class RefreshTokenDetails {

  private final String refreshToken;

  public RefreshTokenDetails(String refreshToken) {
    this.refreshToken = refreshToken;
  }

  public String getRefreshToken() {
    return refreshToken;
  }
}
