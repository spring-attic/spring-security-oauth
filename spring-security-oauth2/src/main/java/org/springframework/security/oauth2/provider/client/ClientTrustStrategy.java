package org.springframework.security.oauth2.provider.client;

import org.springframework.security.oauth2.provider.code.AuthorizationRequestHolder;


/**
 * <p>
 * This is an interface which is responsible for deciding whether the client
 * can skip the confirmation step for a given user.
 * </p>
 * 
 * @author Vladimir Kryachko
 */
public interface ClientTrustStrategy {
	
	boolean canSkipApproval(AuthorizationRequestHolder requestHolder);

}
