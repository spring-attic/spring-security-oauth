package org.springframework.security.oauth2.provider;

import java.util.Map;
import java.util.Set;

import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;

/**
 * Default implementation of {@link OAuth2RequestValidator}. 
 * 
 * @author Amanda Anganes
 *
 */
public class DefaultOAuth2RequestValidator implements OAuth2RequestValidator {

	
	public void validateScope(Map<String, String> parameters, Set<String> clientScopes) {
		if (parameters.containsKey("scope")) {
			if (clientScopes != null && !clientScopes.isEmpty()) {
				for (String scope : OAuth2Utils.parseParameterList(parameters.get("scope"))) {
					if (!clientScopes.contains(scope)) {
						throw new InvalidScopeException("Invalid scope: " + scope, clientScopes);
					}
				}
			}
		}
	}

}
