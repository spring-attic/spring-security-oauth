package org.springframework.security.oauth2.provider.client;

import java.util.Set;

import org.springframework.security.oauth2.provider.code.AuthorizationRequestHolder;

/**
 * The strategy that allows implicit grant requests to bypass user approval page
 * 
 * @author Vladimir Kryachko 
 */
public class ImplicitClientTrustStrategy implements ClientTrustStrategy {

	public boolean canSkipApproval(AuthorizationRequestHolder requestHolder) {
		Set<String> responseTypes = requestHolder.getAuthenticationRequest().getResponseTypes();
		if (responseTypes.contains("code")) {
			return false;
		}
		if (responseTypes.contains("token")) {
			return true;
		}
		return false;
	}

}
