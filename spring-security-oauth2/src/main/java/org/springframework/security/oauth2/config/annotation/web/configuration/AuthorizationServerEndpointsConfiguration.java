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

import java.util.Collections;
import java.util.List;

import javax.annotation.PostConstruct;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerEndpointsConfiguration.TokenStoreRegistrar;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
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
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.security.oauth2.provider.token.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.TokenStore;

/**
 * @author Dave Syer
 *
 */
@Configuration
@Import(TokenStoreRegistrar.class)
public class AuthorizationServerEndpointsConfiguration {

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

	private AuthorizationServerEndpointsConfigurer endpoints = new AuthorizationServerEndpointsConfigurer();

	@Autowired
	private ClientDetailsService clientDetailsService;

	@Autowired
	private List<AuthorizationServerConfigurer> configurers = Collections.emptyList();

	@Autowired(required = false)
	private TokenStore tokenStore;

	@PostConstruct
	public void init() throws Exception {
		for (AuthorizationServerConfigurer configurer : configurers) {
			configurer.configure(endpoints);
		}
		endpoints.clientDetailsService(clientDetailsService);
		if (tokenStore != null) {
			endpoints.tokenStore(tokenStore);
		}
	}

	@Bean
	public AuthorizationEndpoint authorizationEndpoint() throws Exception {
		AuthorizationEndpoint authorizationEndpoint = new AuthorizationEndpoint();
		FrameworkEndpointHandlerMapping mapping = endpoints.getFrameworkEndpointHandlerMapping();
		authorizationEndpoint.setUserApprovalPage(extractPath(mapping, "/oauth/confirm_access"));
		authorizationEndpoint.setErrorPage(extractPath(mapping, "/oauth/error"));
		authorizationEndpoint.setTokenGranter(tokenGranter());
		authorizationEndpoint.setClientDetailsService(clientDetailsService);
		authorizationEndpoint.setAuthorizationCodeServices(authorizationCodeServices());
		authorizationEndpoint.setOAuth2RequestFactory(oauth2RequestFactory());
		authorizationEndpoint.setOAuth2RequestValidator(oauth2RequestValidator());
		authorizationEndpoint.setUserApprovalHandler(userApprovalHandler());
		authorizationEndpoint.setImplicitGrantService(implicitGrantService());
		return authorizationEndpoint;
	}

	public ImplicitGrantService implicitGrantService() throws Exception {
		return endpoints.getImplicitGrantService();
	}

	@Bean
	public ConsumerTokenServices consumerTokenServices() throws Exception {
		return endpoints.getConsumerTokenServices();
	}

	public AuthorizationServerTokenServices authorizationServerTokenServices() throws Exception {
		return endpoints.getTokenServices();
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

	public OAuth2RequestFactory oauth2RequestFactory() throws Exception {
		return endpoints.getOAuth2RequestFactory();
	}

	public UserApprovalHandler userApprovalHandler() throws Exception {
		return endpoints.getUserApprovalHandler();
	}

	public OAuth2RequestValidator oauth2RequestValidator() throws Exception {
		return endpoints.getOAuth2RequestValidator();
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
	public FrameworkEndpointHandlerMapping oauth2EndpointHandlerMapping() throws Exception {
		return endpoints.getFrameworkEndpointHandlerMapping();
	}

	public AuthorizationCodeServices authorizationCodeServices() throws Exception {
		return endpoints.getAuthorizationCodeServices();
	}

	public TokenGranter tokenGranter() throws Exception {
		return endpoints.getTokenGranter();
	}

	private String extractPath(FrameworkEndpointHandlerMapping mapping, String page) {
		String path = mapping.getPath(page);
		if (path.contains(":")) {
			return path;
		}
		return "forward:" + path;
	}

	@Configuration
	protected static class TokenStoreRegistrar implements BeanDefinitionRegistryPostProcessor {

		private BeanDefinitionRegistry registry;

		// Use a BeanFactoryPostProcessor to register a bean definition for a TokenStore in a safe way (without
		// pre-empting a bean specified by the user)
		@Override
		public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
			if (!registry.containsBeanDefinition(TOKEN_STORE_BEAN_NAME)
					&& !registry.containsBeanDefinition(APPROVAL_STORE_BEAN_NAME)) {
				registry.registerBeanDefinition(TOKEN_STORE_BEAN_NAME, new RootBeanDefinition(InMemoryTokenStore.class));
			}
		}

		@Override
		public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) throws BeansException {
			this.registry = registry;
		}

	}

}
