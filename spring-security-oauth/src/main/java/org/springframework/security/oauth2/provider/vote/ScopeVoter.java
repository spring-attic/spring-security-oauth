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
import java.util.Set;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.ClientAuthenticationToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

/**
 * <p> Votes if any {@link ConfigAttribute#getAttribute()} starts with a prefix indicating that it is an OAuth2 scope.
 * The default prefix string is <code>SCOPE_</code>, but this may be overridden to any value. </p>
 * 
 * <p> Abstains from voting if no configuration attribute commences with the scope prefix, or if the current
 * <code>Authentication</code> is not a {@link OAuth2Authentication} or the current client authentication is not a
 * {@link ClientAuthenticationToken} (which contains teh scope data). Votes to grant access if there is an exact
 * matching {@link ClientAuthenticationToken#getScope() authorized scope} to a <code>ConfigAttribute</code> starting
 * with the scope prefix. Votes to deny access if there is no exact matching authorized scope to a
 * <code>ConfigAttribute</code> starting with the scope prefix. </p>
 * 
 * <p> All comparisons and prefixes are case insensitive so you can use (e.g.) <code>SCOPE_READ</code> for simple
 * Facebook-like scope names that might be lower case in the resource definition, or
 * <code>scope=http://my.company.com/scopes/read/</code> for Google-like URI scope names. </p>
 * 
 * @author Dave Syer
 * 
 */
public class ScopeVoter implements AccessDecisionVoter<Object> {

	private String scopePrefix = "SCOPE_";

	public String getScopePrefix() {
		return scopePrefix;
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

	public boolean supports(ConfigAttribute attribute) {
		if ((attribute.getAttribute() != null) && attribute.getAttribute().startsWith(getScopePrefix())) {
			return true;
		} else {
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

		authentication = ((OAuth2Authentication) authentication).getClientAuthentication();

		if (!(authentication instanceof ClientAuthenticationToken)) {
			return result;
		}

		ClientAuthenticationToken clientAuthentication = (ClientAuthenticationToken) authentication;

		for (ConfigAttribute attribute : attributes) {
			if (this.supports(attribute)) {
				result = ACCESS_DENIED;

				Set<String> scopes = clientAuthentication.getScope();
				for (String scope : scopes) {
					if (attribute.getAttribute().equals(scopePrefix + scope.toUpperCase())) {
						return ACCESS_GRANTED;
					}
				}
			}
		}

		return result;
	}

}
