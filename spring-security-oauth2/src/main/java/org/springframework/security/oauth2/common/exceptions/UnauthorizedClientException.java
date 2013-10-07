package org.springframework.security.oauth2.common.exceptions;

/**
 * Exception thrown when a client was unable to authenticate.
 * 
 * @author Ryan Heaton
 */
@SuppressWarnings("serial")
public class UnauthorizedClientException extends ClientAuthenticationException {

	public UnauthorizedClientException(String msg, Throwable t) {
		super(msg, t);
	}

	public UnauthorizedClientException(String msg) {
		super(msg);
	}

	@Override
	public int getHttpErrorCode() {
		// The spec says this can be unauthorized
		return 401;
	}

	@Override
	public String getOAuth2ErrorCode() {
		return "unauthorized_client";
	}
}
