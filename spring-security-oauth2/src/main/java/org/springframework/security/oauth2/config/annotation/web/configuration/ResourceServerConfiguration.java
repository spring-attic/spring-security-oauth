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

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity.RequestMatcherConfigurer;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpointHandlerMapping;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.expression.OAuth2WebSecurityExpressionHandler;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * @author Dave Syer
 * 
 */
@Configuration
@Order(3)
public class ResourceServerConfiguration extends WebSecurityConfigurerAdapter {

	@Autowired
	private TokenStore tokenStore;

	@Autowired(required = false)
	private FrameworkEndpointHandlerMapping frameworkEndpointHandlerMapping;

	private List<ResourceServerConfigurer> configurers = Collections.emptyList();

	private AccessDeniedHandler accessDeniedHandler = new OAuth2AccessDeniedHandler();

	/**
	 * @param configurers the configurers to set
	 */
	@Autowired(required = false)
	public void setConfigurers(List<ResourceServerConfigurer> configurers) {
		this.configurers = configurers;
	}

	private static class NotOAuthRequstMatcher implements RequestMatcher {

		private FrameworkEndpointHandlerMapping mapping;

		public NotOAuthRequstMatcher(FrameworkEndpointHandlerMapping mapping) {
			this.mapping = mapping;
		}

		@Override
		public boolean matches(HttpServletRequest request) {
			String requestPath = getRequestPath(request);
			for (String path : mapping.getPaths()) {
				if (requestPath.startsWith(path)) {
					return false;
				}
			}
			return true;
		}

		private String getRequestPath(HttpServletRequest request) {
			String url = request.getServletPath();

			if (request.getPathInfo() != null) {
				url += request.getPathInfo();
			}

			return url;
		}

	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		RequestMatcherConfigurer requests = http.requestMatchers();
		if (frameworkEndpointHandlerMapping != null) {
			// Assume we are in an Authorization Server
			requests.requestMatchers(new NotOAuthRequstMatcher(frameworkEndpointHandlerMapping));
		}
		// @formatter:off	
		http
			.exceptionHandling().accessDeniedHandler(accessDeniedHandler)
		.and()
			.csrf().disable();
		// @formatter:on
		for (ResourceServerConfigurer configurer : configurers) {
			// Delegates can add authorizeRequests() here
			configurer.configure(http);
		}
		// Add anyRequest() last as a fall back
		http.authorizeRequests().anyRequest().authenticated();
		// And set the default expression handler in case one isn't explicit elsewhere
		http.authorizeRequests().expressionHandler(new OAuth2WebSecurityExpressionHandler());
		OAuth2ResourceServerConfigurer resources = new OAuth2ResourceServerConfigurer();
		http.apply(resources);
		for (ResourceServerConfigurer configurer : configurers) {
			configurer.configure(resources);
		}
		resources.tokenStore(tokenStore);
	}

}
