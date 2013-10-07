package org.springframework.security.oauth2.common.exceptions;

import org.springframework.security.authentication.InsufficientAuthenticationException;

/**
 * @author Ryan Heaton
 */
@SuppressWarnings("serial")
public class UnapprovedClientAuthenticationException extends InsufficientAuthenticationException {

  public UnapprovedClientAuthenticationException(String msg) {
    super(msg);
  }

  public UnapprovedClientAuthenticationException(String msg, Throwable t) {
    super(msg, t);
  }
}
