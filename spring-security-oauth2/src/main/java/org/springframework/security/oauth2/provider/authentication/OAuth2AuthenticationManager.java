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
package org.springframework.security.oauth2.provider.authentication;

import java.util.Collection;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.util.Assert;

/**
 * @author Dave Syer
 * 
 */
public class OAuth2AuthenticationManager implements AuthenticationManager, InitializingBean {

	private ResourceServerTokenServices tokenServices;

	private String resourceId;

	public void setResourceId(String resourceId) {
		this.resourceId = resourceId;
	}

	/**
	 * @param tokenServices the tokenServices to set
	 */
	public void setTokenServices(ResourceServerTokenServices tokenServices) {
		this.tokenServices = tokenServices;
	}

	public void afterPropertiesSet() {
		Assert.state(tokenServices != null, "TokenServices are required");
	}

	public Authentication authenticate(Authentication authentication) throws AuthenticationException {

		String token = (String) authentication.getPrincipal();
		OAuth2Authentication auth = tokenServices.loadAuthentication(token);
		if (auth == null) {
			throw new InvalidTokenException("Invalid token: " + token);
		}

		Collection<String> resourceIds = auth.getAuthorizationRequest().getResourceIds();
		if (resourceId != null && resourceIds != null && !resourceIds.isEmpty() && !resourceIds.contains(resourceId)) {
			throw new OAuth2AccessDeniedException("Invalid token does not contain resource id (" + resourceId + ")");
		}

		return auth;

	}

}
