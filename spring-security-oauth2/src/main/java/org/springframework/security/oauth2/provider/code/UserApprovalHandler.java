package org.springframework.security.oauth2.provider.code;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.AuthorizationRequest;

/**
 * Basic interface for determining whether a given client authentication request has been approved by the current user.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public interface UserApprovalHandler {

	/**
	 * Whether the specified authorization request has been approved by the current user (if there is one).
	 * 
	 * @param authorizationRequest the authorization request.
	 * @param userAuthentication the user authentication for the current user.
	 * @return Whether the specified client authentication has been approved by the current user.
	 */
	boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication);
}
