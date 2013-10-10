package org.springframework.security.oauth2.provider;

import java.util.Set;

import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;

/**
 * Default implementation of {@link OAuth2RequestValidator}. 
 * 
 * @author Amanda Anganes
 *
 */
public class DefaultOAuth2RequestValidator implements OAuth2RequestValidator {

	public void validateScope(AuthorizationRequest authorizationRequest, ClientDetails client) throws InvalidScopeException {
		validateScope(authorizationRequest.getScope(), client.getScope());
	}

	public void validateScope(TokenRequest tokenRequest, ClientDetails client) throws InvalidScopeException {
		validateScope(tokenRequest.getScope(), client.getScope());
	}
	
	private void validateScope(Set<String> requestScopes, Set<String> clientScopes) {

		if (clientScopes != null && !clientScopes.isEmpty()) {
			for (String scope : requestScopes) {
				if (!clientScopes.contains(scope)) {
					throw new InvalidScopeException("Invalid scope: " + scope, clientScopes);
				}
			}
		}
	}

}
