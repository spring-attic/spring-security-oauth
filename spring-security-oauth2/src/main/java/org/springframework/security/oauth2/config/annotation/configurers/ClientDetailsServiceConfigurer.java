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
package org.springframework.security.oauth2.config.annotation.configurers;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.oauth2.config.annotation.builders.ClientDetailsServiceBuilder;
import org.springframework.security.oauth2.config.annotation.builders.InMemoryClientDetailsServiceBuilder;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.ClientDetailsUserDetailsService;

/**
 * @author Rob Winch
 * 
 */
public class ClientDetailsServiceConfigurer extends
		SecurityConfigurerAdapter<AuthenticationManager, AuthenticationManagerBuilder> {

	private ClientDetailsService clientDetailsService;

	@SuppressWarnings("rawtypes")
	private ClientDetailsServiceBuilder builder = new ClientDetailsServiceBuilder();

	public AuthenticationManagerBuilder withClientDetails(ClientDetailsService clientDetailsService) {

		this.clientDetailsService = clientDetailsService;
		return this.and();
	}

	public InMemoryClientDetailsServiceBuilder inMemory() throws Exception {
		InMemoryClientDetailsServiceBuilder next = builder.inMemory();
		this.builder = next;
		return next;
	}

	@Override
	public void init(AuthenticationManagerBuilder builder) throws Exception {
		ClientDetailsService clientDetailsService = this.clientDetailsService != null ? this.clientDetailsService
				: this.builder.build();
		ClientDetailsUserDetailsService userDetailsService = new ClientDetailsUserDetailsService(clientDetailsService);
		builder.userDetailsService(userDetailsService);
		builder.setSharedObject(ClientDetailsService.class, clientDetailsService);
	}

	@Override
	public void configure(AuthenticationManagerBuilder builder) throws Exception {

	}
}
