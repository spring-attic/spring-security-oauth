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
package org.springframework.security.oauth2.config.annotation.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.security.oauth2.config.annotation.builders.ClientDetailsServiceBuilder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;

/**
 * @author Rob Winch
 * 
 */
@Configuration
public class ClientDetailsServiceConfiguration {

	@SuppressWarnings("rawtypes")
	private ClientDetailsServiceConfigurer configurer = new ClientDetailsServiceConfigurer(new ClientDetailsServiceBuilder());
	
	@Bean
	public ClientDetailsServiceConfigurer clientDetailsServiceConfigurer() {
		return configurer;
	}

	@Bean
	@Lazy
	@Scope(proxyMode=ScopedProxyMode.INTERFACES)
	public ClientDetailsService clientDetailsService() throws Exception {
		return configurer.and().build();
	}

}
