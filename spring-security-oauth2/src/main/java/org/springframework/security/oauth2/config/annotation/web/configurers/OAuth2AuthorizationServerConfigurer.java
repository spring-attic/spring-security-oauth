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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.approval.TokenStoreUserApprovalHandler;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenEndpointFilter;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenGranter;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeTokenGranter;
import org.springframework.security.oauth2.provider.code.InMemoryAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.oauth2.provider.implicit.ImplicitGrantService;
import org.springframework.security.oauth2.provider.implicit.ImplicitTokenGranter;
import org.springframework.security.oauth2.provider.implicit.InMemoryImplicitGrantService;
import org.springframework.security.oauth2.provider.password.ResourceOwnerPasswordTokenGranter;
import org.springframework.security.oauth2.provider.refresh.RefreshTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;

/**
 * 
 * @author Rob Winch
 * @since 3.2
 */
public final class OAuth2AuthorizationServerConfigurer extends
		SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

	private AuthenticationEntryPoint authenticationEntryPoint = new OAuth2AuthenticationEntryPoint();

	private AccessDeniedHandler accessDeniedHandler = new OAuth2AccessDeniedHandler();

	private ClientCredentialsTokenEndpointFilter clientCredentialsTokenEndpointFilter;

	private AuthorizationServerTokenServices tokenServices;

	private ConsumerTokenServices consumerTokenServices;

	private AuthorizationCodeServices authorizationCodeServices;

	private ImplicitGrantService implicitGrantService = new InMemoryImplicitGrantService();

	private TokenStore tokenStore;

	private TokenGranter tokenGranter;

	private OAuth2RequestFactory requestFactory;

	private UserApprovalHandler userApprovalHandler;

	private AuthenticationManager authenticationManager;

	private String realm = "oauth2/client";

	private ClientDetailsService clientDetails() {
		return getBuilder().getSharedObject(ClientDetailsService.class);
	}

	public AuthorizationServerTokenServices getTokenServices() {
		return tokenServices;
	}

	public TokenStore getTokenStore() {
		return tokenStore;
	}

	public OAuth2RequestFactory getOAuth2RequestFactory() {
		return requestFactory;
	}

	public UserApprovalHandler getUserApprovalHandler() {
		return userApprovalHandler;
	}

	public OAuth2AuthorizationServerConfigurer tokenStore(TokenStore tokenStore) {
		this.tokenStore = tokenStore;
		return this;
	}

	public OAuth2AuthorizationServerConfigurer userApprovalHandler(UserApprovalHandler approvalHandler) {
		this.userApprovalHandler = approvalHandler;
		return this;
	}

	public OAuth2AuthorizationServerConfigurer realm(String realm) {
		this.realm  = realm;
		return this;
	}

	public OAuth2AuthorizationServerConfigurer authenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
		this.authenticationEntryPoint = authenticationEntryPoint;
		return this;
	}

	public OAuth2AuthorizationServerConfigurer authenticationManager(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
		return this;
	}

	@Override
	public void init(HttpSecurity http) throws Exception {
		registerDefaultAuthenticationEntryPoint(http);
		http.securityContext().securityContextRepository(new NullSecurityContextRepository()).and().csrf().disable()
				.httpBasic().realmName(realm);
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

	@Override
	@SuppressWarnings("unchecked")
	public void configure(HttpSecurity http) throws Exception {
		AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
		clientCredentialsTokenEndpointFilter = new ClientCredentialsTokenEndpointFilter();
		clientCredentialsTokenEndpointFilter.setAuthenticationManager(authenticationManager);
		clientCredentialsTokenEndpointFilter = postProcess(clientCredentialsTokenEndpointFilter);

		this.tokenGranter = tokenGranter(http);
		this.consumerTokenServices = consumerTokenServices(http);
		this.userApprovalHandler = userApprovalHandler();

		// @formatter:off
        http
            .addFilterBefore(clientCredentialsTokenEndpointFilter, BasicAuthenticationFilter.class)
            .getConfigurer(ExceptionHandlingConfigurer.class)
                .accessDeniedHandler(accessDeniedHandler);
        // @formatter:on

	}

	public ConsumerTokenServices getConsumerTokenServices() {
		return consumerTokenServices;
	}
	
	public ImplicitGrantService getImplicitGrantService() {
		return implicitGrantService;
	}

	private ConsumerTokenServices consumerTokenServices(HttpSecurity http) {
		if (consumerTokenServices == null) {
			DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
			defaultTokenServices.setClientDetailsService(clientDetails());
			defaultTokenServices.setTokenStore(tokenStore());
			consumerTokenServices = defaultTokenServices;
		}
		return consumerTokenServices;
	}

	private AuthorizationServerTokenServices tokenServices(HttpSecurity http) {
		if (tokenServices != null) {
			return tokenServices;
		}
		DefaultTokenServices tokenServices = new DefaultTokenServices();
		tokenServices.setTokenStore(tokenStore());
		tokenServices.setSupportRefreshToken(true);
		tokenServices.setClientDetailsService(clientDetails());
		this.tokenServices = tokenServices;
		return tokenServices;
	}

	private TokenStore tokenStore() {
		if (tokenStore == null) {
			this.tokenStore = new InMemoryTokenStore();
		}
		return this.tokenStore;
	}

	private UserApprovalHandler userApprovalHandler() {
		if (userApprovalHandler == null) {
			TokenStoreUserApprovalHandler userApprovalHandler = new TokenStoreUserApprovalHandler();
			userApprovalHandler.setTokenStore(tokenStore());
			userApprovalHandler.setClientDetailsService(clientDetails());
		}
		return this.userApprovalHandler;
	}

	public AuthorizationCodeServices getAuthorizationCodeServices() {
		return authorizationCodeServices;
	}

	private AuthorizationCodeServices authorizationCodeServices(HttpSecurity http) {
		if (authorizationCodeServices == null) {
			authorizationCodeServices = new InMemoryAuthorizationCodeServices();
		}
		return authorizationCodeServices;
	}

	private OAuth2RequestFactory requestFactory(HttpSecurity http) {
		if (requestFactory != null) {
			return requestFactory;
		}
		requestFactory = new DefaultOAuth2RequestFactory(clientDetails());
		return requestFactory;
	}

	public TokenGranter getTokenGranter() {
		return tokenGranter;
	}

	private TokenGranter tokenGranter(HttpSecurity http) throws Exception {
		if (tokenGranter == null) {
			ClientDetailsService clientDetails = clientDetails();
			AuthorizationServerTokenServices tokenServices = tokenServices(http);
			AuthorizationCodeServices authorizationCodeServices = authorizationCodeServices(http);
			OAuth2RequestFactory requestFactory = requestFactory(http);

			List<TokenGranter> tokenGranters = new ArrayList<TokenGranter>();
			tokenGranters.add(new AuthorizationCodeTokenGranter(tokenServices, authorizationCodeServices,
					clientDetails, requestFactory));
			tokenGranters.add(new RefreshTokenGranter(tokenServices, clientDetails, requestFactory));
			ImplicitTokenGranter implicit = new ImplicitTokenGranter(tokenServices, clientDetails, requestFactory);
			implicit.setImplicitGrantService(implicitGrantService);
			tokenGranters.add(implicit);
			tokenGranters.add(new ClientCredentialsTokenGranter(tokenServices, clientDetails, requestFactory));
			if (authenticationManager != null) {
				tokenGranters.add(new ResourceOwnerPasswordTokenGranter(authenticationManager, tokenServices,
						clientDetails, requestFactory));
			}
			tokenGranter = new CompositeTokenGranter(tokenGranters);
		}
		return tokenGranter;
	}
}
