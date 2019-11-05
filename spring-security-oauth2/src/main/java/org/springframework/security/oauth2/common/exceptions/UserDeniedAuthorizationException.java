package org.springframework.security.oauth2.common.exceptions;

/**
 * <p>
 * @deprecated See the <a href="https://github.com/spring-projects/spring-security/wiki/OAuth-2.0-Migration-Guide">OAuth 2.0 Migration Guide</a> for Spring Security 5.
 *
 * @author Ryan Heaton
 */
@SuppressWarnings("serial")
@Deprecated
public class UserDeniedAuthorizationException extends OAuth2Exception {

  public UserDeniedAuthorizationException(String msg, Throwable t) {
    super(msg, t);
  }

  public UserDeniedAuthorizationException(String msg) {
    super(msg);
  }

  @Override
  public String getOAuth2ErrorCode() {
    return "access_denied";
  }

}
