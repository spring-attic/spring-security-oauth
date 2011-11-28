package org.springframework.security.oauth2.client.token.grant.code;

import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class AuthorizationCodeResourceDetails extends BaseOAuth2ProtectedResourceDetails {

	private String userAuthorizationUri;

	private String preEstablishedRedirectUri;

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

	/**
	 * The redirect URI that has been pre-established with the server. If present, the redirect URI will be omitted from
	 * the user authorization request because the server doesn't need to know it.
	 * 
	 * @return The redirect URI that has been pre-established with the server.
	 */
	public String getPreEstablishedRedirectUri() {
		return preEstablishedRedirectUri;
	}

	/**
	 * The redirect URI that has been pre-established with the server. If present, the redirect URI will be omitted from
	 * the user authorization request because the server doesn't need to know it.
	 * 
	 * @param preEstablishedRedirectUri The redirect URI that has been pre-established with the server.
	 */
	public void setPreEstablishedRedirectUri(String preEstablishedRedirectUri) {
		this.preEstablishedRedirectUri = preEstablishedRedirectUri;
	}
}
