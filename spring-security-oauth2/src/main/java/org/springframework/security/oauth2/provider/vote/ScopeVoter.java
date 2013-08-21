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

package org.springframework.security.oauth2.provider.vote;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.InsufficientScopeException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

/**
 * <p>
 * Votes if any {@link ConfigAttribute#getAttribute()} starts with a prefix indicating that it is an OAuth2 scope. The
 * default prefix string is <code>SCOPE_</code>, but this may be overridden to any value. Can also be used to deny
 * access to an OAuth2 client by explicitly specifying an attribute value <code>DENY_OAUTH</code>. Typically you would
 * want to explicitly deny access to all non-public resources that are not part of any scope.
 * </p>
 * 
 * <p>
 * Abstains from voting if no configuration attribute commences with the scope prefix, or if the current
 * <code>Authentication</code> is not a {@link OAuth2Authentication} or the current client authentication is not a
 * {@link AuthorizationRequest} (which contains the scope data). Votes to grant access if there is an exact matching
 * {@link AuthorizationRequest#getScope() authorized scope} to a <code>ConfigAttribute</code> starting with the scope
 * prefix. Votes to deny access if there is no exact matching authorized scope to a <code>ConfigAttribute</code>
 * starting with the scope prefix.
 * </p>
 * 
 * <p>
 * All comparisons and prefixes are case insensitive so you can use (e.g.) <code>SCOPE_READ</code> for simple
 * Facebook-like scope names that might be lower case in the resource definition, or
 * <code>scope=http://my.company.com/scopes/read/</code> (<code>scopePrefix="scope="</code>) for Google-like URI scope
 * names.
 * </p>
 * 
 * @author Dave Syer
 * 
 */
public class ScopeVoter implements AccessDecisionVoter<Object> {

	private String scopePrefix = "SCOPE_";

	private String denyAccess = "DENY_OAUTH";

	private boolean throwException = true;

	/**
	 * Flag to determine the behaviour on access denied. If set then we throw an {@link InsufficientScopeException}
	 * instead of returning {@link AccessDecisionVoter#ACCESS_DENIED}. This is unconventional for an access decision
	 * voter because it vetos the other voters in the chain, but it enables us to pass a message to the caller with
	 * information about the required scope.
	 * 
	 * @param throwException the flag to set (default true)
	 */
	public void setThrowException(boolean throwException) {
		this.throwException = throwException;
	}

	/**
	 * Allows the default role prefix of <code>SCOPE_</code> to be overridden. May be set to an empty value, although
	 * this is usually not desirable.
	 * 
	 * @param scopePrefix the new prefix
	 */
	public void setScopePrefix(String scopePrefix) {
		this.scopePrefix = scopePrefix;
	}

	/**
	 * The name of the config attribute that can be used to deny access to OAuth2 client. Defaults to
	 * <code>DENY_OAUTH</code>.
	 * 
	 * @param denyAccess the deny access attribute value to set
	 */
	public void setDenyAccess(String denyAccess) {
		this.denyAccess = denyAccess;
	}

	public boolean supports(ConfigAttribute attribute) {
		if (denyAccess.equals(attribute.getAttribute()) || (attribute.getAttribute() != null)
				&& attribute.getAttribute().startsWith(scopePrefix)) {
			return true;
		}
		else {
			return false;
		}
	}

	/**
	 * This implementation supports any type of class, because it does not query the presented secure object.
	 * 
	 * @param clazz the secure object
	 * 
	 * @return always <code>true</code>
	 */
	public boolean supports(Class<?> clazz) {
		return true;
	}

	public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {

		int result = ACCESS_ABSTAIN;

		if (!(authentication instanceof OAuth2Authentication)) {
			return result;

		}

		for (ConfigAttribute attribute : attributes) {
			if (denyAccess.equals(attribute.getAttribute())) {
				return ACCESS_DENIED;
			}
		}

		OAuth2Request clientAuthentication = ((OAuth2Authentication) authentication).getOAuth2Request();

		for (ConfigAttribute attribute : attributes) {
			if (this.supports(attribute)) {
				result = ACCESS_DENIED;

				Set<String> scopes = clientAuthentication.getScope();
				for (String scope : scopes) {
					if (attribute.getAttribute().toUpperCase().equals((scopePrefix + scope).toUpperCase())) {
						return ACCESS_GRANTED;
					}
				}
				if (result == ACCESS_DENIED && throwException) {
					InsufficientScopeException failure = new InsufficientScopeException(
							"Insufficient scope for this resource", Collections.singleton(attribute.getAttribute()
									.substring(scopePrefix.length())));
					throw new AccessDeniedException(failure.getMessage(), failure);
				}
			}
		}

		return result;
	}

}
