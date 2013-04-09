package org.springframework.security.oauth2.provider.approval;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.AuthorizationRequest;

/**
 * Basic interface for determining whether a given client authentication request has been approved by the current user.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 * @author Amanda Anganes
 */
public interface UserApprovalHandler {


	/**
	 * <p>
	 * Tests whether the specified authorization request has been approved by the current user (if there is one).
	 * </p>
	 * 
	 * @param authorizationRequest the authorization request.
	 * @param userAuthentication the user authentication for the current user.
	 * @return a new instance or the same one if no changes are required
	 */
	boolean isApproved(AuthorizationRequest authorizationRequest, Authentication userAuthentication);

	/**
	 * <p>
	 * Provides an opportunity to update the authorization request before it is checked for approval in cases where the
	 * incoming approval parameters contain richer information than just true/false (e.g. some scopes are approved, and
	 * others are rejected), implementations may need to be able to modify the {@link AuthorizationRequest} before a
	 * token is generated from it.
	 * </p>
	 * 
	 * @param authorizationRequest the authorization request.
	 * @param userAuthentication TODO
	 * @return a new instance or the same one if no changes are required
	 */
	AuthorizationRequest checkForAutomaticApproval(AuthorizationRequest authorizationRequest, Authentication userAuthentication);

	/**
	 * <p>
	 * Provides an opportunity to update the authorization request before it is checked for approval in cases where the
	 * incoming approval parameters contain richer information than just true/false (e.g. some scopes are approved, and
	 * others are rejected), implementations may need to be able to modify the {@link AuthorizationRequest} before a
	 * token is generated from it.
	 * </p>
	 * 
	 * @param authorizationRequest the authorization request.
	 * @param userAuthentication TODO
	 * @return a new instance or the same one if no changes are required
	 */
	AuthorizationRequest updateAfterApproval(AuthorizationRequest authorizationRequest, Authentication userAuthentication);
}
