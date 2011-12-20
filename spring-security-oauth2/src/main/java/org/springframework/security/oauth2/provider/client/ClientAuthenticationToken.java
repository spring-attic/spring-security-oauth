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
package org.springframework.security.oauth2.provider.client;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

/**
 * @author Dave Syer
 * 
 */
public class ClientAuthenticationToken extends AbstractAuthenticationToken {

	private final String clientId;
	private final String clientSecret;

	public ClientAuthenticationToken(String clientId, String clientSecret,
			Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.clientId = clientId;
		this.clientSecret = clientSecret;
	}

	public ClientAuthenticationToken(String clientId, String clientSecret) {
		this(clientId, clientSecret, null);
	}

	public Object getCredentials() {
		return clientSecret;
	}

	public Object getPrincipal() {
		return clientId;
	}

	public String getClientId() {
		return clientId;
	}

	public String getClientSecret() {
		return clientSecret;
	}	

}
