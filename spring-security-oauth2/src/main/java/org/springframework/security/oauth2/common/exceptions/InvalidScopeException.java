package org.springframework.security.oauth2.common.exceptions;

import java.util.Set;

import org.springframework.security.oauth2.common.util.OAuth2Utils;

/**
 * Exception representing an invalid scope in a token or authorization request (i.e. from an Authorization Server). Note
 * that this is not the same as an access denied exception if the scope presented to a Resource Server is insufficient.
 * The spec is unclear on the correct value for the error code. The bearer spec says 403 (FORBIDDEN), so that's what we
 * use and it seems appropriate (the request is authenticated but not permitted), but it but it seems to be muddled
 * between this and the access denied case on the Resource Server.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class InvalidScopeException extends OAuth2Exception {

	public InvalidScopeException(String msg, Set<String> validScope) {
		this(msg);
		addAdditionalInformation("scope", OAuth2Utils.formatParameterList(validScope));
	}

	public InvalidScopeException(String msg) {
		super(msg);
	}

	@Override
	public int getHttpErrorCode() {
		return 403;
	}

	@Override
	public String getOAuth2ErrorCode() {
		return "invalid_scope";
	}

}