package org.springframework.security.oauth2.common.exceptions;

import org.springframework.security.authentication.InsufficientAuthenticationException;

/**
 * <p>
 * @deprecated See the <a href="https://github.com/spring-projects/spring-security/wiki/OAuth-2.0-Migration-Guide">OAuth 2.0 Migration Guide</a> for Spring Security 5.
 *
 * @author Ryan Heaton
 */
@SuppressWarnings("serial")
@Deprecated
public class UnapprovedClientAuthenticationException extends InsufficientAuthenticationException {

  public UnapprovedClientAuthenticationException(String msg) {
    super(msg);
  }

  public UnapprovedClientAuthenticationException(String msg, Throwable t) {
    super(msg, t);
  }
}
