package org.springframework.security.oauth2.provider;

import java.util.Map;
import java.util.Set;

import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;

/**
 * Validation interface for OAuth2 requests to the {@link AuthorizationEndpoint} and {@link TokenEndpoint}.
 * 
 * @author Amanda Anganes
 *
 */
public interface OAuth2RequestValidator {

	/**
	 * Ensure that the client has requested a valid set of scopes.
	 * 
	 * @param parameters the parameters on the request, including scope
	 * @param clientScopes the requesting client's registered, allowed scopes
	 * @throws InvalidScopeException if a requested scope is invalid
	 */
	public void validateScope(Map<String, String> parameters, Set<String> clientScopes) throws InvalidScopeException;
	
}
