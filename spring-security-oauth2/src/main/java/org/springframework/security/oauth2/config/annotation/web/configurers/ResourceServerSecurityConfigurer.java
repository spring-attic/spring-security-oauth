/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.oauth2.config.annotation.web.configurers;

import java.util.Collections;

import org.springframework.http.MediaType;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.springframework.security.oauth2.provider.authentication.TokenExtractor;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.oauth2.provider.expression.OAuth2WebSecurityExpressionHandler;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;

/**
 *
 * @author Rob Winch
 * @author Dave Syer
 * 
 * @since 2.0.0
 */
public final class ResourceServerSecurityConfigurer extends
		SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

	private AuthenticationEntryPoint authenticationEntryPoint = new OAuth2AuthenticationEntryPoint();

	private AccessDeniedHandler accessDeniedHandler = new OAuth2AccessDeniedHandler();

	private OAuth2AuthenticationProcessingFilter resourcesServerFilter;

	private AuthenticationManager authenticationManager;

	private AuthenticationEventPublisher eventPublisher = null;

	private ResourceServerTokenServices resourceTokenServices;

	private TokenStore tokenStore = new InMemoryTokenStore();

	private String resourceId = "oauth2-resource";

	private SecurityExpressionHandler<FilterInvocation> expressionHandler = new OAuth2WebSecurityExpressionHandler();

	private TokenExtractor tokenExtractor;

	private boolean stateless = true;

	public ResourceServerSecurityConfigurer() {
		resourceId(resourceId);
	}

	private ClientDetailsService clientDetails() {
		return getBuilder().getSharedObject(ClientDetailsService.class);
	}

	public TokenStore getTokenStore() {
		return tokenStore;
	}

	/**
	 * Flag to indicate that only token-based authentication is allowed on these resources.
	 * @param stateless the flag value (default true)
	 * @return this (for fluent builder)
	 */
	public ResourceServerSecurityConfigurer stateless(boolean stateless) {
		this.stateless = stateless;
		return this;
	}

	public ResourceServerSecurityConfigurer authenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
		this.authenticationEntryPoint = authenticationEntryPoint;
		return this;
	}

	public ResourceServerSecurityConfigurer accessDeniedHandler(AccessDeniedHandler accessDeniedHandler) {
		this.accessDeniedHandler = accessDeniedHandler;
		return this;
	}

	public ResourceServerSecurityConfigurer tokenStore(TokenStore tokenStore) {
		Assert.state(tokenStore != null, "TokenStore cannot be null");
		this.tokenStore = tokenStore;
		return this;
	}

	public ResourceServerSecurityConfigurer eventPublisher(AuthenticationEventPublisher eventPublisher) {
		Assert.state(eventPublisher != null, "AuthenticationEventPublisher cannot be null");
		this.eventPublisher = eventPublisher;
		return this;
	}

	public ResourceServerSecurityConfigurer expressionHandler(
			SecurityExpressionHandler<FilterInvocation> expressionHandler) {
		Assert.state(expressionHandler != null, "SecurityExpressionHandler cannot be null");
		this.expressionHandler = expressionHandler;
		return this;
	}

	public ResourceServerSecurityConfigurer tokenExtractor(TokenExtractor tokenExtractor) {
		Assert.state(tokenExtractor != null, "TokenExtractor cannot be null");
		this.tokenExtractor = tokenExtractor;
		return this;
	}

	public ResourceServerSecurityConfigurer authenticationManager(AuthenticationManager authenticationManager) {
		Assert.state(authenticationManager != null, "AuthenticationManager cannot be null");
		this.authenticationManager = authenticationManager;
		return this;
	}

	public ResourceServerSecurityConfigurer tokenServices(ResourceServerTokenServices tokenServices) {
		Assert.state(tokenServices != null, "ResourceServerTokenServices cannot be null");
		this.resourceTokenServices = tokenServices;
		return this;
	}

	@Override
	public void init(HttpSecurity http) throws Exception {
		registerDefaultAuthenticationEntryPoint(http);
	}

	@SuppressWarnings("unchecked")
	private void registerDefaultAuthenticationEntryPoint(HttpSecurity http) {
		ExceptionHandlingConfigurer<HttpSecurity> exceptionHandling = http
				.getConfigurer(ExceptionHandlingConfigurer.class);
		if (exceptionHandling == null) {
			return;
		}
		ContentNegotiationStrategy contentNegotiationStrategy = http.getSharedObject(ContentNegotiationStrategy.class);
		if (contentNegotiationStrategy == null) {
			contentNegotiationStrategy = new HeaderContentNegotiationStrategy();
		}
		MediaTypeRequestMatcher preferredMatcher = new MediaTypeRequestMatcher(contentNegotiationStrategy,
				MediaType.APPLICATION_ATOM_XML, MediaType.APPLICATION_FORM_URLENCODED, MediaType.APPLICATION_JSON,
				MediaType.APPLICATION_OCTET_STREAM, MediaType.APPLICATION_XML, MediaType.MULTIPART_FORM_DATA,
				MediaType.TEXT_XML);
		preferredMatcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
		exceptionHandling.defaultAuthenticationEntryPointFor(postProcess(authenticationEntryPoint), preferredMatcher);
	}

	public ResourceServerSecurityConfigurer resourceId(String resourceId) {
		this.resourceId = resourceId;
		if (authenticationEntryPoint instanceof OAuth2AuthenticationEntryPoint) {
			((OAuth2AuthenticationEntryPoint) authenticationEntryPoint).setRealmName(resourceId);
		}
		return this;
	}

	@Override
	public void configure(HttpSecurity http) throws Exception {

		AuthenticationManager oauthAuthenticationManager = oauthAuthenticationManager(http);
		resourcesServerFilter = new OAuth2AuthenticationProcessingFilter();
		resourcesServerFilter.setAuthenticationEntryPoint(authenticationEntryPoint);
		resourcesServerFilter.setAuthenticationManager(oauthAuthenticationManager);
		if (eventPublisher != null) {
			resourcesServerFilter.setAuthenticationEventPublisher(eventPublisher);
		}
		if (tokenExtractor != null) {
			resourcesServerFilter.setTokenExtractor(tokenExtractor);
		}
		resourcesServerFilter = postProcess(resourcesServerFilter);
		resourcesServerFilter.setStateless(stateless);

		// @formatter:off
		http
			.authorizeRequests().expressionHandler(expressionHandler)
		.and()
			.addFilterBefore(resourcesServerFilter, AbstractPreAuthenticatedProcessingFilter.class)
			.exceptionHandling()
				.accessDeniedHandler(accessDeniedHandler)
				.authenticationEntryPoint(authenticationEntryPoint);
		// @formatter:on
	}

	private AuthenticationManager oauthAuthenticationManager(HttpSecurity http) {
		OAuth2AuthenticationManager oauthAuthenticationManager = new OAuth2AuthenticationManager();
		if (authenticationManager != null) {
			if (authenticationManager instanceof OAuth2AuthenticationManager) {
				oauthAuthenticationManager = (OAuth2AuthenticationManager) authenticationManager;
			}
			else {
				return authenticationManager;
			}
		}
		oauthAuthenticationManager.setResourceId(resourceId);
		oauthAuthenticationManager.setTokenServices(resourceTokenServices(http));
		oauthAuthenticationManager.setClientDetailsService(clientDetails());
		return oauthAuthenticationManager;
	}

	private ResourceServerTokenServices resourceTokenServices(HttpSecurity http) {
		tokenServices(http);
		return this.resourceTokenServices;
	}

	private ResourceServerTokenServices tokenServices(HttpSecurity http) {
		if (resourceTokenServices != null) {
			return resourceTokenServices;
		}
		DefaultTokenServices tokenServices = new DefaultTokenServices();
		tokenServices.setTokenStore(tokenStore());
		tokenServices.setSupportRefreshToken(true);
		tokenServices.setClientDetailsService(clientDetails());
		this.resourceTokenServices = tokenServices;
		return tokenServices;
	}

	private TokenStore tokenStore() {
		Assert.state(tokenStore != null, "TokenStore cannot be null");
		return this.tokenStore;
	}

	public AccessDeniedHandler getAccessDeniedHandler() {
		return this.accessDeniedHandler;
	}

}
