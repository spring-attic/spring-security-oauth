package org.springframework.security.oauth2.client.token.grant.code;

import org.springframework.security.oauth2.client.token.grant.redirect.AbstractRedirectResourceDetails;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class AuthorizationCodeResourceDetails extends AbstractRedirectResourceDetails {

	private String userAuthorizationUri;

	public AuthorizationCodeResourceDetails() {
		setGrantType("authorization_code");
	}

	/**
	 * The URI to which the user is to be redirected to authorize an access token.
	 * 
	 * @return The URI to which the user is to be redirected to authorize an access token.
	 */
	public String getUserAuthorizationUri() {
		return userAuthorizationUri;
	}

	/**
	 * The URI to which the user is to be redirected to authorize an access token.
	 * 
	 * @param userAuthorizationUri The URI to which the user is to be redirected to authorize an access token.
	 */
	public void setUserAuthorizationUri(String userAuthorizationUri) {
		this.userAuthorizationUri = userAuthorizationUri;
	}

}
