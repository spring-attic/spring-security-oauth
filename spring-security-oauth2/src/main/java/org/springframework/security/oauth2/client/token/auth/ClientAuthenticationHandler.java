package org.springframework.security.oauth2.client.token.auth;

import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.util.MultiValueMap;

/**
 * Logic for handling client authentication.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public interface ClientAuthenticationHandler {

	/**
	 * Authenticate a token request.
	 * 
	 * @param resource The resource for which to authenticate a request.
	 * @param form The form that is being submitted as the token request.
	 * @param headers The request headers to be submitted.
	 */
	void authenticateTokenRequest(OAuth2ProtectedResourceDetails resource, MultiValueMap<String, String> form,
			HttpHeaders headers);
}
