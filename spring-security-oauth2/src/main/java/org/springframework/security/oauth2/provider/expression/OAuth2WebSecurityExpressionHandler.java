/*
 * Copyright 2006-2011 the original author or authors.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.oauth2.provider.expression;

import org.springframework.security.access.expression.AbstractSecurityExpressionHandler;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.WebSecurityExpressionRoot;

/**
 * @author Dave Syer
 * 
 */
public class OAuth2WebSecurityExpressionHandler extends AbstractSecurityExpressionHandler<FilterInvocation> {

	@Override
	protected SecurityExpressionRoot createSecurityExpressionRoot(Authentication authentication, FilterInvocation fi) {
		OAuth2WebSecurityExpressionRoot root = new OAuth2WebSecurityExpressionRoot(authentication, fi);
		root.setPermissionEvaluator(getPermissionEvaluator());
		return root;
	}

	private static class OAuth2WebSecurityExpressionRoot extends WebSecurityExpressionRoot {

		private final Authentication authentication;

		public OAuth2WebSecurityExpressionRoot(Authentication authentication, FilterInvocation fi) {
			super(authentication, fi);
			this.authentication = authentication;
		}

		/**
		 * Public method exposed to expressions in the security filter.
		 * 
		 * @param role the role to check
		 * @return true if the OAuth2 client has this role
		 */
		@SuppressWarnings("unused")
		public boolean oauthClientHasRole(String role) {
			return oauthClientHasAnyRole(role);
		}

		/**
		 * Public method exposed to expressions in the security filter.
		 * 
		 * @param roles the roles to check
		 * @return true if the OAuth2 client has one of these roles
		 */
		public boolean oauthClientHasAnyRole(String... roles) {
			return OAuth2ExpressionUtils.clientHasAnyRole(authentication, roles);
		}

		/**
		 * Public method exposed to expressions in the security filter used to deny access to oauth requests (so only
		 * allow web UI users to access a resource for instance).
		 * 
		 * @return true if the current authentication is not an OAuth2 type
		 */
		@SuppressWarnings("unused")
		public boolean denyOAuthClient() {
			return !OAuth2ExpressionUtils.isOAuthClientAuth(authentication);
		}

	}
}