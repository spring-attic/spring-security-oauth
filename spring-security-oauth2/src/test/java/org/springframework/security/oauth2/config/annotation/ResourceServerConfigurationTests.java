/*
 * Copyright 2006-2011 the original author or authors.
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
package org.springframework.security.oauth2.config.annotation;

import java.util.Collections;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.authentication.TokenExtractor;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.InMemoryClientDetailsService;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.filter.DelegatingFilterProxy;

/**
 * @author Dave Syer
 * 
 */
public class ResourceServerConfigurationTests {

	private static InMemoryTokenStore tokenStore = new InMemoryTokenStore();

	private OAuth2AccessToken token;

	private OAuth2Authentication authentication;

	@Rule
	public ExpectedException expected = ExpectedException.none();

	@Before
	public void init() {
		token = new DefaultOAuth2AccessToken("FOO");
		ClientDetails client = new BaseClientDetails("client", null, "read",
				"client_credentials", "ROLE_CLIENT");
		authentication = new OAuth2Authentication(
				new TokenRequest(null, "client", null, "client_credentials")
						.createOAuth2Request(client),
				null);
		tokenStore.clear();
	}

	@Test
	public void testDefaults() throws Exception {
		tokenStore.storeAccessToken(token, authentication);
		AnnotationConfigWebApplicationContext context = new AnnotationConfigWebApplicationContext();
		context.setServletContext(new MockServletContext());
		context.register(ResourceServerContext.class);
		context.refresh();
		MockMvc mvc = MockMvcBuilders
				.webAppContextSetup(context)
				.addFilters(
						new DelegatingFilterProxy(context.getBean(
								"springSecurityFilterChain", Filter.class)))
				.build();
		mvc.perform(MockMvcRequestBuilders.get("/")).andExpect(
				MockMvcResultMatchers.status().isUnauthorized());
		mvc.perform(
				MockMvcRequestBuilders.get("/").header("Authorization",
						"Bearer FOO")).andExpect(
				MockMvcResultMatchers.status().isNotFound());
		context.close();
	}

	@Test
	public void testWithAuthServer() throws Exception {
		AnnotationConfigWebApplicationContext context = new AnnotationConfigWebApplicationContext();
		context.setServletContext(new MockServletContext());
		context.register(ResourceServerAndAuthorizationServerContext.class);
		context.refresh();
		context.close();
	}

	@Test
	public void testWithAuthServerAndGlobalMethodSecurity() throws Exception {
		AnnotationConfigWebApplicationContext context = new AnnotationConfigWebApplicationContext();
		context.setServletContext(new MockServletContext());
		context.register(ResourceServerAndAuthorizationServerContextAndGlobalMethodSecurity.class);
		context.refresh();
		context.close();
	}

	@Test
	public void testCustomTokenServices() throws Exception {
		tokenStore.storeAccessToken(token, authentication);
		AnnotationConfigWebApplicationContext context = new AnnotationConfigWebApplicationContext();
		context.setServletContext(new MockServletContext());
		context.register(TokenServicesContext.class);
		context.refresh();
		MockMvc mvc = MockMvcBuilders
				.webAppContextSetup(context)
				.addFilters(
						new DelegatingFilterProxy(context.getBean(
								"springSecurityFilterChain", Filter.class)))
				.build();
		mvc.perform(MockMvcRequestBuilders.get("/")).andExpect(
				MockMvcResultMatchers.status().isUnauthorized());
		mvc.perform(
				MockMvcRequestBuilders.get("/").header("Authorization",
						"Bearer FOO")).andExpect(
				MockMvcResultMatchers.status().isNotFound());
		context.close();
	}

	@Test
	public void testCustomTokenExtractor() throws Exception {
		tokenStore.storeAccessToken(token, authentication);
		AnnotationConfigWebApplicationContext context = new AnnotationConfigWebApplicationContext();
		context.setServletContext(new MockServletContext());
		context.register(TokenExtractorContext.class);
		context.refresh();
		MockMvc mvc = MockMvcBuilders
				.webAppContextSetup(context)
				.addFilters(
						new DelegatingFilterProxy(context.getBean(
								"springSecurityFilterChain", Filter.class)))
				.build();
		mvc.perform(
				MockMvcRequestBuilders.get("/").header("Authorization",
						"Bearer BAR")).andExpect(
				MockMvcResultMatchers.status().isNotFound());
		context.close();
	}

	@Test
	public void testCustomExpressionHandler() throws Exception {
		tokenStore.storeAccessToken(token, authentication);
		AnnotationConfigWebApplicationContext context = new AnnotationConfigWebApplicationContext();
		context.setServletContext(new MockServletContext());
		context.register(ExpressionHandlerContext.class);
		context.refresh();
		MockMvc mvc = MockMvcBuilders
				.webAppContextSetup(context)
				.addFilters(
						new DelegatingFilterProxy(context.getBean(
								"springSecurityFilterChain", Filter.class)))
				.build();
		expected.expect(IllegalArgumentException.class);
		expected.expectMessage("#oauth2");
		mvc.perform(
				MockMvcRequestBuilders.get("/").header("Authorization",
						"Bearer FOO")).andExpect(
				MockMvcResultMatchers.status().isUnauthorized());
		context.close();
	}

	@Test
	public void testCustomAuthenticationEntryPoint() throws Exception {
		tokenStore.storeAccessToken(token, authentication);
		AnnotationConfigWebApplicationContext context = new AnnotationConfigWebApplicationContext();
		context.setServletContext(new MockServletContext());
		context.register(AuthenticationEntryPointContext.class);
		context.refresh();
		MockMvc mvc = MockMvcBuilders
				.webAppContextSetup(context)
				.addFilters(
						new DelegatingFilterProxy(context.getBean(
								"springSecurityFilterChain", Filter.class)))
				.build();
		mvc.perform(
				MockMvcRequestBuilders.get("/").header("Authorization",
						"Bearer FOO")).andExpect(
				MockMvcResultMatchers.status().isFound());
		context.close();
	}

	@Configuration
	@EnableResourceServer
	@EnableWebSecurity
	protected static class ResourceServerContext {
		@Bean
		public TokenStore tokenStore() {
			return tokenStore;
		}
	}

	@Configuration
	@EnableResourceServer
	@EnableAuthorizationServer
	@EnableWebSecurity
	protected static class ResourceServerAndAuthorizationServerContext extends
			AuthorizationServerConfigurerAdapter {
		@Override
		public void configure(ClientDetailsServiceConfigurer clients)
				throws Exception {
			clients.inMemory();
		}
	}

	@Configuration
	@EnableResourceServer
	@EnableAuthorizationServer
	@EnableWebSecurity
	@EnableGlobalMethodSecurity(prePostEnabled = true, proxyTargetClass = true)
	protected static class ResourceServerAndAuthorizationServerContextAndGlobalMethodSecurity
			extends AuthorizationServerConfigurerAdapter {
		@Override
		public void configure(ClientDetailsServiceConfigurer clients)
				throws Exception {
			clients.inMemory();
		}
	}

	@Configuration
	@EnableResourceServer
	@EnableWebSecurity
	protected static class AuthenticationEntryPointContext extends
			ResourceServerConfigurerAdapter {

		@Override
		public void configure(HttpSecurity http) throws Exception {
			http.authorizeRequests().anyRequest().authenticated();
		}

		@Override
		public void configure(ResourceServerSecurityConfigurer resources)
				throws Exception {
			resources.authenticationEntryPoint(authenticationEntryPoint());
		}

		private AuthenticationEntryPoint authenticationEntryPoint() {
			return new LoginUrlAuthenticationEntryPoint("/login");
		}

	}

	@Configuration
	@EnableResourceServer
	@EnableWebSecurity
	protected static class TokenExtractorContext extends
			ResourceServerConfigurerAdapter {
		@Override
		public void configure(ResourceServerSecurityConfigurer resources)
				throws Exception {
			resources.tokenExtractor(new TokenExtractor() {

				@Override
				public Authentication extract(HttpServletRequest request) {
					return new PreAuthenticatedAuthenticationToken("FOO", "N/A");
				}
			}).tokenStore(tokenStore());
		}

		@Override
		public void configure(HttpSecurity http) throws Exception {
			http.authorizeRequests().anyRequest().access("#oauth2.isClient()");
		}

		@Bean
		public TokenStore tokenStore() {
			return tokenStore;
		}
	}

	@Configuration
	@EnableResourceServer
	@EnableWebSecurity
	protected static class ExpressionHandlerContext extends
			ResourceServerConfigurerAdapter {
		@Override
		public void configure(ResourceServerSecurityConfigurer resources)
				throws Exception {
			resources
					.expressionHandler(new DefaultWebSecurityExpressionHandler());
		}

		@Override
		public void configure(HttpSecurity http) throws Exception {
			http.authorizeRequests().anyRequest().access("#oauth2.isClient()");
		}

		@Bean
		public TokenStore tokenStore() {
			return tokenStore;
		}
	}

	@Configuration
	@EnableResourceServer
	@EnableWebSecurity
	protected static class TokenServicesContext {

		@Bean
		protected ClientDetailsService clientDetailsService() {
			InMemoryClientDetailsService service = new InMemoryClientDetailsService();
			service.setClientDetailsStore(Collections.singletonMap("client",
					new BaseClientDetails("client", null, null, null, null)));
			return service;
		}

		@Bean
		public DefaultTokenServices tokenServices() {
			DefaultTokenServices tokenServices = new DefaultTokenServices();
			tokenServices.setTokenStore(tokenStore());
			tokenServices.setClientDetailsService(clientDetailsService());
			return tokenServices;
		}

		@Bean
		public TokenStore tokenStore() {
			return tokenStore;
		}
	}

}