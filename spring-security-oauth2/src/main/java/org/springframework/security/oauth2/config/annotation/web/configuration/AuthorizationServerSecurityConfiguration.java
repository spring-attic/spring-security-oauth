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
package org.springframework.security.oauth2.config.annotation.web.configuration;

import java.util.Collections;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.config.annotation.configuration.ClientDetailsServiceConfiguration;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpointHandlerMapping;

/**
 * @author Rob Winch
 * @author Dave Syer
 * 
 */
@Configuration
@Order(0)
@Import({ ClientDetailsServiceConfiguration.class, AuthorizationServerEndpointsConfiguration.class })
public class AuthorizationServerSecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Autowired
	private List<AuthorizationServerConfigurer> configurers = Collections.emptyList();

	@Autowired
	private ClientDetailsService clientDetailsService;

	@Autowired
	private AuthorizationServerEndpointsConfiguration endpoints;

	@Autowired
	public void configure(ClientDetailsServiceConfigurer clientDetails) throws Exception {
		for (AuthorizationServerConfigurer configurer : configurers) {
			configurer.configure(clientDetails);
		}
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		AuthorizationServerSecurityConfigurer configurer = new AuthorizationServerSecurityConfigurer();
		FrameworkEndpointHandlerMapping handlerMapping = endpoints.oauth2EndpointHandlerMapping();
		http.setSharedObject(FrameworkEndpointHandlerMapping.class, handlerMapping);
		configure(configurer);
		http.apply(configurer);
		String tokenEndpointPath = handlerMapping.getServletPath("/oauth/token");
		String tokenKeyPath = handlerMapping.getServletPath("/oauth/token_key");
		String checkTokenPath = handlerMapping.getServletPath("/oauth/check_token");
		if (!endpoints.getEndpointsConfigurer().isUserDetailsServiceOverride()) {
			UserDetailsService userDetailsService = http.getSharedObject(UserDetailsService.class);
			endpoints.getEndpointsConfigurer().userDetailsService(userDetailsService);
		}
		// @formatter:off
		http
        	.authorizeRequests()
            	.antMatchers(tokenEndpointPath).fullyAuthenticated()
            	.antMatchers(tokenKeyPath).access(configurer.getTokenKeyAccess())
            	.antMatchers(checkTokenPath).access(configurer.getCheckTokenAccess())
        .and()
        	.requestMatchers()
            	.antMatchers(tokenEndpointPath, tokenKeyPath, checkTokenPath)
        .and()
        	.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER);
		// @formatter:on
		http.setSharedObject(ClientDetailsService.class, clientDetailsService);
	}

	protected void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
		for (AuthorizationServerConfigurer configurer : configurers) {
			configurer.configure(oauthServer);
		}
	}

}
