package org.springframework.security.oauth2.common.exceptions;

/**
 * Exception thrown when a client was unable to authenticate.
 *
 * @author Ryan Heaton
 * @author Dave Syer
 */
@SuppressWarnings("serial")
public class BadClientCredentialsException extends ClientAuthenticationException {

	public BadClientCredentialsException() {
		super("Bad client credentials"); // Don't reveal source of error
	}

	@Override
	public int getHttpErrorCode() {
		return 401;
	}

	@Override
	public String getOAuth2ErrorCode() {
		return "invalid_client";
	}
}
