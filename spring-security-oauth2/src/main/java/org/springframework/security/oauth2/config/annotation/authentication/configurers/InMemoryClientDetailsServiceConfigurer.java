/*
 * Copyright 2002-2013 the original author or authors.
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
package org.springframework.security.oauth2.config.annotation.authentication.configurers;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.InMemoryClientDetailsService;
import org.springframework.security.oauth2.provider.client.ClientDetailsUserDetailsService;

/**
 * @author Rob Winch
 * 
 */
public class InMemoryClientDetailsServiceConfigurer extends
		SecurityConfigurerAdapter<AuthenticationManager, AuthenticationManagerBuilder> {
	private List<ClientBuilder> clientBuilders = new ArrayList<ClientBuilder>();

	public ClientBuilder withClient(String clientId) {
		ClientBuilder clientBuilder = new ClientBuilder(clientId);
		this.clientBuilders.add(clientBuilder);
		return clientBuilder;
	}

	@Override
	public void init(AuthenticationManagerBuilder builder) throws Exception {
		Map<String, ClientDetails> clientDetails = new HashMap<String, ClientDetails>(clientBuilders.size());
		for (ClientBuilder clientDetailsBldr : clientBuilders) {
			clientDetails.put(clientDetailsBldr.clientId, clientDetailsBldr.build());
		}
		InMemoryClientDetailsService clientDetailsService = new InMemoryClientDetailsService();
		clientDetailsService.setClientDetailsStore(clientDetails);

		ClientDetailsUserDetailsService userDetailsService = new ClientDetailsUserDetailsService(clientDetailsService);
		builder.userDetailsService(userDetailsService);

		builder.setSharedObject(ClientDetailsService.class, clientDetailsService);
	}

	@Override
	public void configure(AuthenticationManagerBuilder builder) throws Exception {

	}

	public final class ClientBuilder {
		private final String clientId;

		private Collection<String> authorizedGrantTypes = new LinkedHashSet<String>();

		private Collection<String> authorities = new LinkedHashSet<String>();

		private Integer accessTokenValiditySeconds;

		private Integer refreshTokenValiditySeconds;

		private Collection<String> scopes = new LinkedHashSet<String>();

		private Collection<String> autoApproveScopes = new HashSet<String>();

		private String secret;

		private Set<String> registeredRedirectUris = new HashSet<String>();

		private Set<String> resourceIds = new HashSet<String>();

		private boolean autoApprove;

		private ClientDetails build() {
			BaseClientDetails result = new BaseClientDetails();
			result.setClientId(clientId);
			result.setAuthorizedGrantTypes(authorizedGrantTypes);
			result.setAccessTokenValiditySeconds(accessTokenValiditySeconds);
			result.setRefreshTokenValiditySeconds(refreshTokenValiditySeconds);
			result.setRegisteredRedirectUri(registeredRedirectUris);
			result.setClientSecret(secret);
			result.setScope(scopes);
			result.setAuthorities(AuthorityUtils.createAuthorityList(authorities.toArray(new String[authorities.size()])));
			result.setResourceIds(resourceIds);
			if (autoApprove) {
				result.setAutoApproveScopes(scopes);
			}
			return result;
		}

		public ClientBuilder resourceIds(String... resourceIds) {
			for (String resourceId : resourceIds) {
				this.resourceIds.add(resourceId);
			}
			return this;
		}

		public ClientBuilder redirectUris(String... registeredRedirectUris) {
			for (String redirectUri : registeredRedirectUris) {
				this.registeredRedirectUris.add(redirectUri);
			}
			return this;
		}

		public ClientBuilder authorizedGrantTypes(String... authorizedGrantTypes) {
			for (String grant : authorizedGrantTypes) {
				this.authorizedGrantTypes.add(grant);
			}
			return this;
		}

		public ClientBuilder accessTokenValiditySeconds(int accessTokenValiditySeconds) {
			this.accessTokenValiditySeconds = accessTokenValiditySeconds;
			return this;
		}

		public ClientBuilder refreshTokenValiditySeconds(int refreshTokenValiditySeconds) {
			this.refreshTokenValiditySeconds = refreshTokenValiditySeconds;
			return this;
		}

		public ClientBuilder secret(String secret) {
			this.secret = secret;
			return this;
		}

		public ClientBuilder scopes(String... scopes) {
			for (String scope : scopes) {
				this.scopes.add(scope);
			}
			return this;
		}

		public ClientBuilder authorities(String... authorities) {
			for (String authority : authorities) {
				this.authorities.add(authority);
			}
			return this;
		}

		public ClientBuilder autoApprove(boolean autoApprove) {
			this.autoApprove = autoApprove;
			return this;
		}

		public ClientBuilder autoApprove(String... scopes) {
			for (String scope : scopes) {
				this.autoApproveScopes.add(scope);
			}
			return this;
		}

		public InMemoryClientDetailsServiceConfigurer and() {
			return InMemoryClientDetailsServiceConfigurer.this;
		}

		private ClientBuilder(String clientId) {
			this.clientId = clientId;
		}

	}
}
