package org.springframework.security.oauth2.common.exceptions;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
@SuppressWarnings("serial")
public class InvalidGrantException extends ClientAuthenticationException {

	public InvalidGrantException(String msg, Throwable t) {
		super(msg, t);
	}

	public InvalidGrantException(String msg) {
		super(msg);
	}

	@Override
	public String getOAuth2ErrorCode() {
		return "invalid_grant";
	}
}