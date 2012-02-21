package org.springframework.security.oauth2.provider.client;

import org.springframework.security.oauth2.provider.code.AuthorizationRequestHolder;

/**
 * Strategy that always returns false
 * 
 * @author Vladimir Kryachko
 *
 */
public class NotTrustedClientTrustStrategy implements ClientTrustStrategy {

	public boolean canSkipApproval(AuthorizationRequestHolder requestHolder) {
		return false;
	}

}
