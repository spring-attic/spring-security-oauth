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

	
	public void validateScope(Set<String> requestScopes, ClientDetails client) {

		Set<String> clientScopes = client.getScope();
		
		if (clientScopes != null && !clientScopes.isEmpty()) {
			for (String scope : requestScopes) {
				if (!clientScopes.contains(scope)) {
					throw new InvalidScopeException("Invalid scope: " + scope, clientScopes);
				}
			}
		}
	}

}
