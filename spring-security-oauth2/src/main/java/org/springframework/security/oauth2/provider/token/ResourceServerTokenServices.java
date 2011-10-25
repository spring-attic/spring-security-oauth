package org.springframework.security.oauth2.provider.token;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

public interface ResourceServerTokenServices {

	/**
	 * Load the credentials for the specified access token.
	 *
	 * @param accessToken The access token value.
	 * @return The authentication for the access token.
	 * @throws AuthenticationException If the access token is expired
	 */
	OAuth2Authentication loadAuthentication(String accessToken) throws AuthenticationException;

}