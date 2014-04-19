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

import java.util.Set;

import org.springframework.security.core.GrantedAuthority;

/**
 * Strategy for accessing useful information about the current security context.
 * 
 * @author Dave Syer
 *
 */
public interface SecurityContextAccessor {

	/**
	 * @return true if the current context represents a user
	 */
	boolean isUser();

	/**
	 * Get the current granted authorities (never null)
	 */
	Set<GrantedAuthority> getAuthorities();

}
