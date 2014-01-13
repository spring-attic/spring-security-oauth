package org.springframework.security.oauth2.common.exceptions;

/**
 * Exception thrown when a user was unable to authenticate.
 * 
 * @author Dave Syer
 */
@SuppressWarnings("serial")
public class UnauthorizedUserException extends OAuth2Exception {

	public UnauthorizedUserException(String msg, Throwable t) {
		super(msg, t);
	}

	public UnauthorizedUserException(String msg) {
		super(msg);
	}

	@Override
	public int getHttpErrorCode() {
		// The spec says this can be unauthorized
		return 401;
	}

	@Override
	public String getOAuth2ErrorCode() {
		// Not in the spec
		return "unauthorized_user";
	}
}
