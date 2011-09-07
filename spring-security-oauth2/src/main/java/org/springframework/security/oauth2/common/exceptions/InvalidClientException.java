package org.springframework.security.oauth2.common.exceptions;

/**
 * Exception thrown when a client was unable to authenticate.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class InvalidClientException extends ClientAuthenticationException {

	public InvalidClientException(String msg, Throwable t) {
		super(msg, t);
	}

	public InvalidClientException(String msg) {
		super(msg);
	}

	public InvalidClientException(String msg, Object extraInformation) {
		super(msg, extraInformation);
	}

	@Override
	public int getHttpErrorCode() {
		// TODO: The spec says this is a bad request (not unauthorized) unless the client has attempted authentication
		return 401;
	}

	@Override
	public String getOAuth2ErrorCode() {
		return "invalid_client";
	}
}
