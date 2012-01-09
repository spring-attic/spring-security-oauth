/*
 * Copyright 2002-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.provider.expression;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.WebSecurityExpressionRoot;

/**
 * Root for access decision expressions extending the standard Spring Security methods to include OAuth2 specific public
 * methods.
 * 
 * @author Dave Syer
 * 
 */
public class OAuth2WebSecurityExpressionRoot extends WebSecurityExpressionRoot {

	private final Authentication authentication;

	public OAuth2WebSecurityExpressionRoot(Authentication authentication, FilterInvocation fi) {
		super(authentication, fi);
		this.authentication = authentication;
	}

	/**
	 * Check if the OAuth2 client (not the user) has the role specified. To check the user's roles see
	 * {@link #hasRole(String)}.
	 * 
	 * @param role the role to check
	 * @return true if the OAuth2 client has this role
	 */
	public boolean oauthClientHasRole(String role) {
		return oauthClientHasAnyRole(role);
	}

	/**
	 * Check if the OAuth2 client (not the user) has one of the roles specified. To check the user's roles see
	 * {@link #hasAnyRole(String)}.
	 * 
	 * @param roles the roles to check
	 * @return true if the OAuth2 client has one of these roles
	 */
	public boolean oauthClientHasAnyRole(String... roles) {
		return OAuth2ExpressionUtils.clientHasAnyRole(authentication, roles);
	}

	/**
	 * Deny access to oauth requests, so used for example to only allow web UI users to access a resource.
	 * 
	 * @return true if the current authentication is not an OAuth2 type
	 */
	public boolean denyOAuthClient() {
		return !OAuth2ExpressionUtils.isOAuthClientAuth(authentication);
	}

}