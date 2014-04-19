/*
 * Copyright 2013-2014 the original author or authors.
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

package org.springframework.security.oauth2.provider;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Strategy for accessing useful information about the current security context.
 * 
 * @author Dave Syer
 * 
 */
public class DefaultSecurityContextAccessor implements SecurityContextAccessor {

	@Override
	public boolean isUser() {
		Authentication authentication = getUserAuthentication();
		return authentication != null;
	}
	
	@Override
	public Set<GrantedAuthority> getAuthorities() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null) {
			return Collections.emptySet();
		}
		return Collections.unmodifiableSet(new HashSet<GrantedAuthority>(authentication.getAuthorities()));
	}

	private Authentication getUserAuthentication() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null) {
			return null;
		}
		if (authentication instanceof OAuth2Authentication) {
			OAuth2Authentication oauth = (OAuth2Authentication) authentication;
			return oauth.getUserAuthentication();
		}
		return authentication;
	}

}
