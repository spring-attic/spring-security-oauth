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

package org.springframework.security.oauth2.config.annotation.web.configuration;

import java.util.Map;

import javax.annotation.Resource;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.util.ClassUtils;
import org.springframework.util.ObjectUtils;
import org.springframework.web.context.ConfigurableWebEnvironment;
import org.springframework.web.context.WebApplicationContext;

/**
 * @author Dave Syer
 * 
 */
@Configuration
public class OAuth2ClientConfiguration {

	@Bean
	public OAuth2ClientContextFilter oauth2ClientContextFilter() {
		OAuth2ClientContextFilter filter = new OAuth2ClientContextFilter();
		return filter;
	}

	@Bean
	@Scope(value = "request", proxyMode = ScopedProxyMode.INTERFACES)
	protected AccessTokenRequest accessTokenRequest(@Value("#{request.parameterMap}")
	Map<String, String[]> parameters, @Value("#{request.getAttribute('currentUri')}")
	String currentUri) {
		DefaultAccessTokenRequest request = new DefaultAccessTokenRequest(parameters);
		request.setCurrentUri(currentUri);
		return request;
	}
	
	@Configuration
	protected static class OAuth2ClientContextConfiguration {
		
		@Resource
		@Qualifier("accessTokenRequest")
		private AccessTokenRequest accessTokenRequest;
		
		@Bean
		@Scope(value = "session", proxyMode = ScopedProxyMode.INTERFACES)
		@Conditional(OnWebApplicationCondition.class)
		public OAuth2ClientContext oauth2ClientContext() {
			return new DefaultOAuth2ClientContext(accessTokenRequest);
		}
		
	}

	// logic borrowed from Spring Boot's OnWebApplicationCondition
	private static class OnWebApplicationCondition implements Condition {

		@Override
		public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
			if (!ClassUtils.isPresent("org.springframework.web.context.support.GenericWebApplicationContext",
					context.getClassLoader())) {
				return false;
			}
			if (context.getBeanFactory() != null) {
				String[] scopes = context.getBeanFactory().getRegisteredScopeNames();
				if (ObjectUtils.containsElement(scopes, "session")) {
					return true;
				}
			}
			if (context.getEnvironment() instanceof ConfigurableWebEnvironment) {
				return true;
			}
			if (context.getResourceLoader() instanceof WebApplicationContext) {
				return true;
			}
			return false;
		}
	}

}
