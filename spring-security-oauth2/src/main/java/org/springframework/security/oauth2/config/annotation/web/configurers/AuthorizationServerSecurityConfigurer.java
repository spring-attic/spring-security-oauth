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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.OAuth2RequestValidator;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.ApprovalStoreUserApprovalHandler;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenStoreUserApprovalHandler;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenEndpointFilter;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenGranter;
import org.springframework.security.oauth2.provider.client.ClientDetailsUserDetailsService;
import org.springframework.security.oauth2.provider.client.InMemoryClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeTokenGranter;
import org.springframework.security.oauth2.provider.code.InMemoryAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpointHandlerMapping;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.oauth2.provider.implicit.ImplicitGrantService;
import org.springframework.security.oauth2.provider.implicit.ImplicitTokenGranter;
import org.springframework.security.oauth2.provider.implicit.InMemoryImplicitGrantService;
import org.springframework.security.oauth2.provider.password.ResourceOwnerPasswordTokenGranter;
import org.springframework.security.oauth2.provider.refresh.RefreshTokenGranter;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestValidator;
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
public final class AuthorizationServerSecurityConfigurer extends
		SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

	private AuthenticationEntryPoint authenticationEntryPoint = new OAuth2AuthenticationEntryPoint();

	private AccessDeniedHandler accessDeniedHandler = new OAuth2AccessDeniedHandler();

	private AuthorizationServerTokenServices tokenServices;

	private ConsumerTokenServices consumerTokenServices;

	private AuthorizationCodeServices authorizationCodeServices;

	private ImplicitGrantService implicitGrantService = new InMemoryImplicitGrantService();

	private TokenStore tokenStore;

	private ApprovalStore approvalStore;

	private TokenGranter tokenGranter;

	private OAuth2RequestFactory requestFactory;

	private OAuth2RequestValidator requestValidator;

	private UserApprovalHandler userApprovalHandler;

	private AuthenticationManager authenticationManager;

	private ClientDetailsService clientDetailsService;

	private String realm = "oauth2/client";

	private Map<String, String> patternMap = new HashMap<String, String>();

	private FrameworkEndpointHandlerMapping frameworkEndpointHandlerMapping;

	private boolean allowFormAuthenticationForClients = false;

	private boolean approvalStoreDisabled;

	private ClientDetailsService clientDetails() {
		return getBuilder().getSharedObject(ClientDetailsService.class);
	}

	public AuthorizationServerTokenServices getTokenServices() {
		return tokenServices;
	}

	public TokenStore getTokenStore() {
		return tokenStore;
	}

	public ApprovalStore getApprovalStore() {
		return approvalStore;
	}

	public ClientDetailsService getClientDetailsService() {
		return clientDetailsService;
	}

	public OAuth2RequestFactory getOAuth2RequestFactory() {
		return requestFactory;
	}

	public OAuth2RequestValidator getOAuth2RequestValidator() {
		return requestValidator;
	}

	public UserApprovalHandler getUserApprovalHandler() {
		return userApprovalHandler;
	}

	public AuthorizationServerSecurityConfigurer allowFormAuthenticationForClients() {
		this.allowFormAuthenticationForClients = true;
		return this;
	}

	public AuthorizationServerSecurityConfigurer tokenStore(TokenStore tokenStore) {
		this.tokenStore = tokenStore;
		return this;
	}

	public AuthorizationServerSecurityConfigurer tokenService(AuthorizationServerTokenServices tokenServices) {
		this.tokenServices = tokenServices;
		return this;
	}

	public AuthorizationServerSecurityConfigurer userApprovalHandler(UserApprovalHandler approvalHandler) {
		this.userApprovalHandler = approvalHandler;
		return this;
	}

	public AuthorizationServerSecurityConfigurer approvalStore(ApprovalStore approvalStore) {
		if (approvalStoreDisabled) {
			throw new IllegalStateException("ApprovalStore was disabled");
		}
		this.approvalStore = approvalStore;
		return this;
	}

	public AuthorizationServerSecurityConfigurer approvalStoreDisabled() {
		this.approvalStoreDisabled = true;
		return this;
	}

	public AuthorizationServerSecurityConfigurer realm(String realm) {
		this.realm = realm;
		return this;
	}

	public AuthorizationServerSecurityConfigurer pathMapping(String defaultPath, String customPath) {
		this.patternMap.put(defaultPath, customPath);
		return this;
	}

	public AuthorizationServerSecurityConfigurer authenticationEntryPoint(
			AuthenticationEntryPoint authenticationEntryPoint) {
		this.authenticationEntryPoint = authenticationEntryPoint;
		return this;
	}

	public AuthorizationServerSecurityConfigurer authenticationManager(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
		return this;
	}

	public AuthorizationServerSecurityConfigurer tokenGranter(TokenGranter tokenGranter) {
		this.tokenGranter = tokenGranter;
		return this;
	}

	public AuthorizationServerSecurityConfigurer clientDetailsService(ClientDetailsService clientDetailsService) {
		this.clientDetailsService = clientDetailsService;
		return this;
	}

	public AuthorizationServerSecurityConfigurer requestFactory(OAuth2RequestFactory requestFactory) {
		this.requestFactory = requestFactory;
		return this;
	}

	public AuthorizationServerSecurityConfigurer requestValidator(OAuth2RequestValidator requestValidator) {
		this.requestValidator = requestValidator;
		return this;
	}

	public AuthorizationServerSecurityConfigurer authorizationCodeServices(AuthorizationCodeServices authorizationCodeServices) {
		this.authorizationCodeServices = authorizationCodeServices;
		return this;
	}

	@Override
	public void init(HttpSecurity http) throws Exception {
		registerDefaultAuthenticationEntryPoint(http);
		http.userDetailsService(new ClientDetailsUserDetailsService(clientDetailsService())).securityContext()
				.securityContextRepository(new NullSecurityContextRepository()).and().csrf().disable().httpBasic()
				.realmName(realm);
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
	public void configure(HttpSecurity http) throws Exception {

		this.tokenGranter = tokenGranter(http);
		this.consumerTokenServices = consumerTokenServices(http);
		this.userApprovalHandler = userApprovalHandler(http);

		// ensure this is initialized
		frameworkEndpointHandlerMapping();
		if (allowFormAuthenticationForClients) {
			clientCredentialsTokenEndpointFilter(http);
		}
		requestValidator(http);

		http.exceptionHandling().accessDeniedHandler(accessDeniedHandler);

	}

	private ClientCredentialsTokenEndpointFilter clientCredentialsTokenEndpointFilter(HttpSecurity http) {
		ClientCredentialsTokenEndpointFilter clientCredentialsTokenEndpointFilter = new ClientCredentialsTokenEndpointFilter(
				frameworkEndpointHandlerMapping().getPath("/oauth/token"));
		clientCredentialsTokenEndpointFilter
				.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));
		clientCredentialsTokenEndpointFilter = postProcess(clientCredentialsTokenEndpointFilter);
		http.addFilterBefore(clientCredentialsTokenEndpointFilter, BasicAuthenticationFilter.class);
		return clientCredentialsTokenEndpointFilter;
	}

	public ConsumerTokenServices getConsumerTokenServices() {
		return consumerTokenServices;
	}

	public ImplicitGrantService getImplicitGrantService() {
		return implicitGrantService;
	}

	private ConsumerTokenServices consumerTokenServices(HttpSecurity http) {
		if (consumerTokenServices == null) {
			if (tokenStore() != null) {
				DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
				defaultTokenServices.setClientDetailsService(clientDetails());
				defaultTokenServices.setTokenStore(tokenStore());
				consumerTokenServices = defaultTokenServices;
			}
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
		if (tokenStore == null && approvalStore == null) {
			this.tokenStore = new InMemoryTokenStore();
		}
		return this.tokenStore;
	}

	private ApprovalStore approvalStore() {
		if (approvalStore==null && tokenStore() != null && !approvalStoreDisabled) {
			TokenApprovalStore tokenApprovalStore = new TokenApprovalStore();
			tokenApprovalStore.setTokenStore(tokenStore());
			this.approvalStore = tokenApprovalStore;
		}
		return this.approvalStore;
	}

	private ClientDetailsService clientDetailsService() {
		if (clientDetailsService == null) {
			this.clientDetailsService = new InMemoryClientDetailsService();
		}
		return this.clientDetailsService;
	}

	private UserApprovalHandler userApprovalHandler(HttpSecurity http) {
		if (userApprovalHandler == null) {
			if (approvalStore()!=null) {
				ApprovalStoreUserApprovalHandler handler = new ApprovalStoreUserApprovalHandler();
				handler.setApprovalStore(approvalStore());
				handler.setRequestFactory(requestFactory);
				handler.setClientDetailsService(clientDetailsService);
				this.userApprovalHandler = handler;				
			}
			else if (tokenStore() != null) {
				TokenStoreUserApprovalHandler userApprovalHandler = new TokenStoreUserApprovalHandler();
				userApprovalHandler.setTokenStore(tokenStore());
				userApprovalHandler.setClientDetailsService(clientDetails());
				userApprovalHandler.setRequestFactory(requestFactory(http));
				this.userApprovalHandler = userApprovalHandler;
			} else {
				throw new IllegalStateException("Either a TokenStore or an ApprovalStore must be provided");
			}
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

	private OAuth2RequestValidator requestValidator(HttpSecurity http) {
		if (requestValidator != null) {
			return requestValidator;
		}
		requestValidator = new DefaultOAuth2RequestValidator();
		return requestValidator;
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

	public FrameworkEndpointHandlerMapping getFrameworkEndpointHandlerMapping() {
		return frameworkEndpointHandlerMapping();
	}

	private FrameworkEndpointHandlerMapping frameworkEndpointHandlerMapping() {
		if (frameworkEndpointHandlerMapping == null) {
			frameworkEndpointHandlerMapping = new FrameworkEndpointHandlerMapping();
			frameworkEndpointHandlerMapping.setMappings(patternMap);
		}
		return frameworkEndpointHandlerMapping;
	}
}
