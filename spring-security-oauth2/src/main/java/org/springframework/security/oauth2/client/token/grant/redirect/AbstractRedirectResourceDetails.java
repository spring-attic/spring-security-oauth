package org.springframework.security.oauth2.client.token.grant.redirect;

import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;

/**
 * @author Dave Syer
 */
public abstract class AbstractRedirectResourceDetails extends BaseOAuth2ProtectedResourceDetails {

	private String preEstablishedRedirectUri;
	
	private String userAuthorizationUri;

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

	/**
	 * Extract a redirect uri from the resource and/or the current request.
	 * 
	 * @param request the current {@link DefaultAccessTokenRequest}
	 * @return a redirect uri if one can be established
	 */
	public String getRedirectUri(AccessTokenRequest request) {

		String redirectUri = request.getFirst("redirect_uri"); 

		if (redirectUri == null && request.getCurrentUri() != null) {
			redirectUri = request.getCurrentUri();
		}

		if (redirectUri == null && getPreEstablishedRedirectUri() != null) {
			// Override the redirect_uri if it is pre-registered
			redirectUri = getPreEstablishedRedirectUri();
		}

		return redirectUri;

	}

}
