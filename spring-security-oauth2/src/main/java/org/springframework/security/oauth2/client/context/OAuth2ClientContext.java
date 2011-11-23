package org.springframework.security.oauth2.client.context;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

/**
 * The OAuth 2 security context (for a specific user or client).
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class OAuth2ClientContext {

	private final Map<String, OAuth2AccessToken> accessTokens;

	private final Map<String, OAuth2ProtectedResourceDetails> resources = new HashMap<String, OAuth2ProtectedResourceDetails>();

	public OAuth2ClientContext() {
		this(Collections.<String, OAuth2AccessToken> emptyMap());
	}

	public OAuth2ClientContext(Map<String, OAuth2AccessToken> accessTokens) {
		this.accessTokens = new ConcurrentHashMap<String, OAuth2AccessToken>(accessTokens);
	}

	public OAuth2AccessToken getAccessToken(OAuth2ProtectedResourceDetails resource) {
		return accessTokens.get(resource.getId());
	}

	public void removeAccessToken(OAuth2ProtectedResourceDetails resource) {
		accessTokens.remove(resource.getId());
		resources.remove(resource.getId());
	}

	public boolean containsResource(OAuth2ProtectedResourceDetails resource) {
		return accessTokens.containsKey(resource.getId());
	}

	public void addAccessToken(OAuth2ProtectedResourceDetails resource, OAuth2AccessToken accessToken) {
		accessTokens.put(resource.getId(), accessToken);
		resources.put(resource.getId(), resource);
	}

	public Map<OAuth2ProtectedResourceDetails, OAuth2AccessToken> getNewAccessTokens() {
		Map<OAuth2ProtectedResourceDetails, OAuth2AccessToken> result = new HashMap<OAuth2ProtectedResourceDetails, OAuth2AccessToken>();
		for (String id : resources.keySet()) {
			result.put(resources.get(id), accessTokens.get(id));
		}
		return result;
	}

}
