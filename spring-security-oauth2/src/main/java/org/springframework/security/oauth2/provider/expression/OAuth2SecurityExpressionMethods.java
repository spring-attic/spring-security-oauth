/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */

package org.springframework.security.oauth2.provider.expression;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.InsufficientScopeException;

/**
 * A convenience object for security expressions in OAuth2 protected resources, providing public methods that act on the
 * current authentication.
 * 
 * @author Dave Syer
 * @author Rob Winch
 * 
 */
public class OAuth2SecurityExpressionMethods {

	private final Authentication authentication;

	private Set<String> missingScopes = new LinkedHashSet<String>();

	private boolean throwExceptionOnInvalidScope;

	public OAuth2SecurityExpressionMethods(Authentication authentication, boolean throwExceptionOnInvalidScope) {
		this.authentication = authentication;
		this.throwExceptionOnInvalidScope = throwExceptionOnInvalidScope;
	}

	/**
	 * Check if any scope decisions have been denied in the current context and throw an exception if so. Example usage:
	 * 
	 * <pre>
	 * access = &quot;#oauth2.sufficientScope(#oauth2.hasScope('read') or (#oauth2.hasScope('other') and hasRole('ROLE_USER')))&quot;
	 * </pre>
	 * 
	 * @param decision the existing access decision
	 * @return true if the OAuth2 token has one of these scopes
	 * @throws InsufficientScopeException if the scope is invalid and we the flag is set to throw the exception
	 */
	public boolean sufficientScope(boolean decision) {
		if (!decision && !missingScopes.isEmpty()) {
			throw new InsufficientScopeException("Insufficient scope for this resource", missingScopes);
		}
		return decision;
	}

	/**
	 * Check if the OAuth2 client (not the user) has the role specified. To check the user's roles see
	 * {@link #hasRole(String)}.
	 * 
	 * @param role the role to check
	 * @return true if the OAuth2 client has this role
	 */
	public boolean clientHasRole(String role) {
		return clientHasAnyRole(role);
	}

	/**
	 * Check if the OAuth2 client (not the user) has one of the roles specified. To check the user's roles see
	 * {@link #hasAnyRole(String)}.
	 * 
	 * @param roles the roles to check
	 * @return true if the OAuth2 client has one of these roles
	 */
	public boolean clientHasAnyRole(String... roles) {
		return OAuth2ExpressionUtils.clientHasAnyRole(authentication, roles);
	}

	/**
	 * Check if the current OAuth2 authentication has one of the scopes specified.
	 * 
	 * @param scope the scope to check
	 * @return true if the OAuth2 authentication has the required scope
	 */
	public boolean hasScope(String scope) {
		return hasAnyScope(scope);
	}

	/**
	 * Check if the current OAuth2 authentication has one of the scopes specified.
	 * 
	 * @param roles the scopes to check
	 * @return true if the OAuth2 token has one of these scopes
	 * @throws InsufficientScopeException if the scope is invalid and we the flag is set to throw the exception
	 */
	public boolean hasAnyScope(String... scopes) {
		boolean result = OAuth2ExpressionUtils.hasAnyScope(authentication, scopes);
		if (!result && throwExceptionOnInvalidScope) {
			missingScopes.addAll(Arrays.asList(scopes));
			throw new InsufficientScopeException("Insufficient scope for this resource", missingScopes);
		}
		return result;
	}

	/**
	 * Deny access to oauth requests, so used for example to only allow web UI users to access a resource.
	 * 
	 * @return true if the current authentication is not an OAuth2 type
	 */
	public boolean denyOAuthClient() {
		return !OAuth2ExpressionUtils.isOAuth(authentication);
	}

	/**
	 * Check if the current authentication is acting on behalf of an authenticated user.
	 * 
	 * @return true if the current authentication represents a user
	 */
	public boolean isUser() {
		return OAuth2ExpressionUtils.isOAuthUserAuth(authentication);
	}

	/**
	 * Check if the current authentication is acting as an authenticated client application not on behalf of a user.
	 * 
	 * @return true if the current authentication represents a client application
	 */
	public boolean isClient() {
		return OAuth2ExpressionUtils.isOAuthClientAuth(authentication);
	}

	/**
	 * A flag to indicate that an exception should be thrown if a scope decision is negative.
	 * 
	 * @param throwExceptionOnInvalidScope flag value (default true)
	 */
	public void setThrowExceptionOnInvalidScope(boolean throwExceptionOnInvalidScope) {
		this.throwExceptionOnInvalidScope = throwExceptionOnInvalidScope;
	}
}
