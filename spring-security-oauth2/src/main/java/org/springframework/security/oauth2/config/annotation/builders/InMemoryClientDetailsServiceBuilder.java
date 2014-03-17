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

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.InMemoryClientDetailsService;

/**
 * @author Dave Syer
 * 
 */
public class InMemoryClientDetailsServiceBuilder extends
		ClientDetailsServiceBuilder<InMemoryClientDetailsServiceBuilder> {

	private Map<String, ClientDetails> clientDetails = new HashMap<String, ClientDetails>();

	@Override
	protected void addClient(String clientId, ClientDetails value) {
		clientDetails.put(clientId, value);
	}

	@Override
	protected ClientDetailsService performBuild() {
		InMemoryClientDetailsService clientDetailsService = new InMemoryClientDetailsService();
		clientDetailsService.setClientDetailsStore(clientDetails);
		return clientDetailsService;
	}

}
