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

import java.util.Collection;
import java.util.Set;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

/**
 * @author Dave Syer
 * @author Radek Ostrowski
 * 
 */
public abstract class OAuth2ExpressionUtils {

	public static boolean clientHasAnyRole(Authentication authentication, String... roles) {
		if (authentication instanceof OAuth2Authentication) {
			OAuth2Request clientAuthentication = ((OAuth2Authentication) authentication).getOAuth2Request();
			Collection<? extends GrantedAuthority> clientAuthorities = clientAuthentication.getAuthorities();
			if (clientAuthorities != null) {
				Set<String> roleSet = AuthorityUtils.authorityListToSet(clientAuthorities);
				for (String role : roles) {
					if (roleSet.contains(role)) {
						return true;
					}
				}
			}
		}
	
		return false;
	}

	public static boolean isOAuth(Authentication authentication) {
		
		if (authentication instanceof OAuth2Authentication) {
			return true;
		}
	
		return false;
	}

	public static boolean isOAuthClientAuth(Authentication authentication) {
		
		if (authentication instanceof OAuth2Authentication) {
			return authentication.isAuthenticated() && ((OAuth2Authentication)authentication).isClientOnly();
		}
	
		return false;
	}

	public static boolean isOAuthUserAuth(Authentication authentication) {
		
		if (authentication instanceof OAuth2Authentication) {
			return authentication.isAuthenticated() && !((OAuth2Authentication)authentication).isClientOnly();
		}
	
		return false;
	}

	public static boolean hasAnyScope(Authentication authentication, String[] scopes) {

		if (authentication instanceof OAuth2Authentication) {
			OAuth2Request clientAuthentication = ((OAuth2Authentication) authentication).getOAuth2Request();
			Collection<String> assigned = clientAuthentication.getScope();
			if (assigned != null) {
				for (String scope : scopes) {
					if (assigned.contains(scope)) {
						return true;
					}
				}
			}
		}
	
		return false;
	}

	public static boolean hasAnyScopeMatching(Authentication authentication, String[] scopesRegex) {

		if (authentication instanceof OAuth2Authentication) {
			OAuth2Request clientAuthentication = ((OAuth2Authentication) authentication).getOAuth2Request();
			for (String scope : clientAuthentication.getScope()) {
				for (String regex : scopesRegex) {
					if (scope.matches(regex)) {
						return true;
					}
				}
			}
		}

		return false;
	}

}
