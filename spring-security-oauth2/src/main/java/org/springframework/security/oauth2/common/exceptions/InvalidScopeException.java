package org.springframework.security.oauth2.common.exceptions;

import java.util.Set;

import org.springframework.security.oauth2.common.util.OAuth2Utils;

/**
 * Exception representing an invalid scope in a token or authorization request (i.e. from an Authorization Server). Note
 * that this is not the same as an access denied exception if the scope presented to a Resource Server is insufficient.
 * The spec in this case mandates a 400 status code.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
@SuppressWarnings("serial")
public class InvalidScopeException extends OAuth2Exception {

	public InvalidScopeException(String msg, Set<String> validScope) {
		this(msg);
		addAdditionalInformation("scope", OAuth2Utils.formatParameterList(validScope));
	}

	public InvalidScopeException(String msg) {
		super(msg);
	}

	@Override
	public String getOAuth2ErrorCode() {
		return "invalid_scope";
	}

}