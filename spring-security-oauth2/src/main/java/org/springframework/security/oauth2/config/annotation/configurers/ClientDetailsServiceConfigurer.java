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

import javax.sql.DataSource;

import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.builders.ClientDetailsServiceBuilder;
import org.springframework.security.oauth2.config.annotation.builders.InMemoryClientDetailsServiceBuilder;
import org.springframework.security.oauth2.config.annotation.builders.JdbcClientDetailsServiceBuilder;
import org.springframework.security.oauth2.provider.ClientDetailsService;

/**
 * @author Rob Winch
 * 
 */
public class ClientDetailsServiceConfigurer extends
		SecurityConfigurerAdapter<ClientDetailsService, ClientDetailsServiceBuilder<?>> {

	public ClientDetailsServiceConfigurer(ClientDetailsServiceBuilder<?> builder) {
		setBuilder(builder);
	}

	public ClientDetailsServiceBuilder<?> withClientDetails(ClientDetailsService clientDetailsService) throws Exception {
		setBuilder(getBuilder().clients(clientDetailsService));
		return this.and();
	}

	public InMemoryClientDetailsServiceBuilder inMemory() throws Exception {
		InMemoryClientDetailsServiceBuilder next = getBuilder().inMemory();
		setBuilder(next);
		return next;
	}
	public JdbcClientDetailsServiceBuilder jdbc(DataSource dataSource) throws Exception {
		JdbcClientDetailsServiceBuilder next = getBuilder().jdbc().dataSource(dataSource);
		setBuilder(next);
		return next;
	}
	
	@Override
	public void init(ClientDetailsServiceBuilder<?> builder) throws Exception {
	}

	@Override
	public void configure(ClientDetailsServiceBuilder<?> builder) throws Exception {
	}

}
