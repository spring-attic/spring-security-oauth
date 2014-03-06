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
package org.springframework.security.oauth2.config.annotation.builders;

import java.util.HashSet;
import java.util.Set;

import javax.sql.DataSource;

import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.JdbcClientDetailsService;
import org.springframework.util.Assert;

/**
 * @author Dave Syer
 * 
 */
public class JdbcClientDetailsServiceBuilder extends
		ClientDetailsServiceBuilder<JdbcClientDetailsServiceBuilder> {

	private Set<ClientDetails> clientDetails = new HashSet<ClientDetails>();
	private DataSource dataSource;
	
	public JdbcClientDetailsServiceBuilder dataSource(DataSource dataSource) {
		this.dataSource = dataSource;
		return this;
	}

	@Override
	protected void addClient(String clientId, ClientDetails value) {
		clientDetails.add(value);
	}

	@Override
	protected ClientDetailsService performBuild() {
		Assert.state(dataSource!=null, "You need to provide a DataSource");
		JdbcClientDetailsService clientDetailsService = new JdbcClientDetailsService(dataSource);
		for (ClientDetails client : clientDetails) {
			clientDetailsService.addClientDetails(client);
		}
		return clientDetailsService;
	}

}
