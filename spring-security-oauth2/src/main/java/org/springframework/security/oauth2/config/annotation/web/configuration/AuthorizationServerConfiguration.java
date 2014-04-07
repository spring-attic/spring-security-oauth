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

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.ImportBeanDefinitionRegistrar;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.core.annotation.Order;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.config.annotation.authentication.configurers.GlobalAuthenticationConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.configuration.ClientDetailsServiceConfiguration;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.OAuth2RequestValidator;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint;
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpointHandlerMapping;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint;
import org.springframework.security.oauth2.provider.endpoint.WhitelabelApprovalEndpoint;
import org.springframework.security.oauth2.provider.endpoint.WhitelabelErrorEndpoint;
import org.springframework.security.oauth2.provider.implicit.ImplicitGrantService;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.security.oauth2.provider.token.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.TokenStore;

/**
 * @author Rob Winch
 * @author Dave Syer
 * 
 */
@Configuration
@Import(ClientDetailsServiceConfiguration.class)
@Order(0)
public class AuthorizationServerConfiguration extends WebSecurityConfigurerAdapter {

	/**
	 * The static bean name for a TokenStore if any. If the use creates his own bean with the same name, or else an
	 * ApprovalStore named {@link #APPROVAL_STORE_BEAN_NAME}, then Spring will create an {@link InMemoryTokenStore}.
	 * 
	 */
	public static final String TOKEN_STORE_BEAN_NAME = "tokenStore";

	/**
	 * The static bean name for a {@link ApprovalStore} if any. Spring will not create one, but it will also not create
	 * a {@link TokenStore} bean if there is an approval store present.
	 */
	public static final String APPROVAL_STORE_BEAN_NAME = "approvalStore";

	@Autowired
	private List<AuthorizationServerConfigurer> configurers = Collections.emptyList();

	@Autowired
	private ClientDetailsService clientDetailsService;

	@Autowired(required = false)
	private TokenStore tokenStore;

	@Configuration
	protected static class ClientDetailsAuthenticationManagerConfiguration extends
			GlobalAuthenticationConfigurerAdapter {

	}

	@Autowired
	public void configure(ClientDetailsServiceConfigurer clientDetails) throws Exception {
		for (AuthorizationServerConfigurer configurer : configurers) {
			configurer.configure(clientDetails);
		}
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		AuthorizationServerSecurityConfigurer configurer = new AuthorizationServerSecurityConfigurer();
		configurer.clientDetailsService(clientDetailsService);
		configure(configurer);
		if (tokenStore != null) {
			configurer.tokenStore(tokenStore);
		}
		http.apply(configurer);
		String tokenEndpointPath = oauth2EndpointHandlerMapping().getPath("/oauth/token");
		// @formatter:off
		http
        .authorizeRequests()
            .antMatchers(tokenEndpointPath).fullyAuthenticated()
            .and()
        .requestMatchers()
            .antMatchers(tokenEndpointPath);
		// @formatter:on
		http.setSharedObject(ClientDetailsService.class, clientDetailsService);
	}

	protected void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
		for (AuthorizationServerConfigurer configurer : configurers) {
			configurer.configure(oauthServer);
		}
	}

	@Bean
	public AuthorizationEndpoint authorizationEndpoint() throws Exception {
		AuthorizationEndpoint authorizationEndpoint = new AuthorizationEndpoint();
		authorizationEndpoint.setTokenGranter(tokenGranter());
		authorizationEndpoint.setClientDetailsService(clientDetailsService);
		authorizationEndpoint.setAuthorizationCodeServices(authorizationCodeServices());
		authorizationEndpoint.setOAuth2RequestFactory(oauth2RequestFactory());
		authorizationEndpoint.setOAuth2RequestValidator(oauth2RequestValidator());
		authorizationEndpoint.setUserApprovalHandler(userApprovalHandler());
		authorizationEndpoint.setImplicitGrantService(implicitGrantService());
		return authorizationEndpoint;
	}

	@Bean
	@Lazy
	@Scope(proxyMode = ScopedProxyMode.INTERFACES)
	public ImplicitGrantService implicitGrantService() throws Exception {
		return authorizationServerConfigurer().getImplicitGrantService();
	}

	@Bean
	@Lazy
	@Scope(proxyMode = ScopedProxyMode.INTERFACES)
	public ConsumerTokenServices consumerTokenServices() throws Exception {
		return authorizationServerConfigurer().getConsumerTokenServices();
	}

	@Bean
	public TokenEndpoint tokenEndpoint() throws Exception {
		TokenEndpoint tokenEndpoint = new TokenEndpoint();
		tokenEndpoint.setClientDetailsService(clientDetailsService);
		tokenEndpoint.setTokenGranter(tokenGranter());
		tokenEndpoint.setOAuth2RequestFactory(oauth2RequestFactory());
		tokenEndpoint.setOAuth2RequestValidator(oauth2RequestValidator());
		return tokenEndpoint;
	}

	@Bean
	@Lazy
	@Scope(proxyMode = ScopedProxyMode.INTERFACES)
	public OAuth2RequestFactory oauth2RequestFactory() throws Exception {
		return authorizationServerConfigurer().getOAuth2RequestFactory();
	}

	@Bean
	@Lazy
	@Scope(proxyMode = ScopedProxyMode.INTERFACES)
	public OAuth2RequestValidator oauth2RequestValidator() throws Exception {
		return authorizationServerConfigurer().getOAuth2RequestValidator();
	}

	@Bean
	@Lazy
	@Scope(proxyMode = ScopedProxyMode.INTERFACES)
	public UserApprovalHandler userApprovalHandler() throws Exception {
		return authorizationServerConfigurer().getUserApprovalHandler();
	}

	@Bean
	public WhitelabelApprovalEndpoint whitelabelApprovalEndpoint() {
		return new WhitelabelApprovalEndpoint();
	}

	@Bean
	public WhitelabelErrorEndpoint whitelabelErrorEndpoint() {
		return new WhitelabelErrorEndpoint();
	}

	@Bean
	@Lazy
	@Scope(proxyMode = ScopedProxyMode.TARGET_CLASS)
	public FrameworkEndpointHandlerMapping oauth2EndpointHandlerMapping() throws Exception {
		return authorizationServerConfigurer().getFrameworkEndpointHandlerMapping();
	}

	@Bean
	@Lazy
	@Scope(proxyMode = ScopedProxyMode.INTERFACES)
	public AuthorizationCodeServices authorizationCodeServices() throws Exception {
		return authorizationServerConfigurer().getAuthorizationCodeServices();
	}

	@Bean
	@Lazy
	@Scope(proxyMode = ScopedProxyMode.INTERFACES)
	public TokenGranter tokenGranter() throws Exception {
		return authorizationServerConfigurer().getTokenGranter();
	}

	private AuthorizationServerSecurityConfigurer authorizationServerConfigurer() throws Exception {
		return getHttp().getConfigurer(AuthorizationServerSecurityConfigurer.class);
	}

	@Configuration
	@Import(TokenStoreRegistrar.class)
	protected static class EndpointsConfiguration {

		@Autowired
		private AuthorizationEndpoint authorizationEndpoint;

		@Autowired(required = false)
		private ApprovalStore approvalStore;

		@Autowired
		private FrameworkEndpointHandlerMapping mapping;

		@PostConstruct
		public void init() {
			if (approvalStore != null) {
				authorizationEndpoint.setApprovalStore(approvalStore);
			}
			authorizationEndpoint.setUserApprovalPage(extractPath(mapping, "/oauth/confirm_access"));
			authorizationEndpoint.setErrorPage(extractPath(mapping, "/oauth/error"));
		}

		private String extractPath(FrameworkEndpointHandlerMapping mapping, String page) {
			String path = mapping.getPath(page);
			if (path.contains(":")) {
				return path;
			}
			return "forward:" + path;
		}

	}

	protected static class TokenStoreRegistrar implements ImportBeanDefinitionRegistrar {

		@Override
		public void registerBeanDefinitions(AnnotationMetadata importingClassMetadata, BeanDefinitionRegistry registry) {
			if (!registry.containsBeanDefinition(TOKEN_STORE_BEAN_NAME)
					&& !registry.containsBeanDefinition(APPROVAL_STORE_BEAN_NAME)) {
				registry.registerBeanDefinition(TOKEN_STORE_BEAN_NAME, new RootBeanDefinition(InMemoryTokenStore.class));
			}
		}

	}

}
