package org.springframework.security.oauth2.client.context;

import java.util.Map;

import org.springframework.security.oauth2.common.OAuth2AccessToken;

/**
 * The OAuth 2 security context (for a specific user).
 *
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class OAuth2ClientContext {

	private Map<String, OAuth2AccessToken> accessTokens;

	public Map<String, OAuth2AccessToken> getAccessTokens() {
		return accessTokens;
	}

	public void setAccessTokens(Map<String, OAuth2AccessToken> accessTokens) {
		this.accessTokens = accessTokens;
	}

}
