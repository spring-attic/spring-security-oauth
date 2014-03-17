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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.List;

import javax.sql.DataSource;

import org.junit.After;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.mockito.Mockito;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.config.annotation.web.servlet.configuration.EnableWebMvcSecurity;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfiguration;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint;
import org.springframework.security.oauth2.provider.token.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.JdbcTokenStore;
import org.springframework.security.oauth2.provider.token.JwtTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

/**
 * @author Dave Syer
 * 
 */
@RunWith(Parameterized.class)
public class AuthorizationServerConfigurationTests {

	private AnnotationConfigWebApplicationContext context;

	@Rule
	public ExpectedException expected = ExpectedException.none();

	private Class<?>[] resources;

	@Parameters
	public static List<Object[]> parameters() {
		return Arrays.asList( // @formatter:off
				new Object[] { BeanCreationException.class,	new Class<?>[] { AuthorizationServerUnconfigured.class } }, 
				new Object[] { null, new Class<?>[] { AuthorizationServerExtras.class } }, 
				new Object[] { null, new Class<?>[] { AuthorizationServerJdbc.class } }, 
				new Object[] { null, new Class<?>[] { AuthorizationServerJwt.class } }, 
				new Object[] { null, new Class<?>[] { AuthorizationServerApproval.class } }, 
				new Object[] { BeanCreationException.class,	new Class<?>[] { AuthorizationServerTypes.class } }	
				// @formatter:on
				);
	}

	public AuthorizationServerConfigurationTests(Class<? extends Exception> error, Class<?>... resource) {
		if (error != null) {
			expected.expect(error);
		}
		this.resources = resource;
		context = new AnnotationConfigWebApplicationContext();
		context.setServletContext(new MockServletContext());
		context.register(resource);
	}

	@After
	public void close() {
		if (context != null) {
			context.close();
		}
	}

	@Test
	public void testDefaults() {
		context.refresh();
		assertTrue(context.containsBeanDefinition("authorizationEndpoint"));
		assertNotNull(context.getBean("authorizationEndpoint", AuthorizationEndpoint.class));
		for (Class<?> resource : resources) {
			if (Runnable.class.isAssignableFrom(resource)) {
				((Runnable) context.getBean(resource)).run();
			}
		}
	}

	@Configuration
	@EnableWebMvcSecurity
	@EnableAuthorizationServer
	protected static class AuthorizationServerUnconfigured {
	}

	@Configuration
	@EnableWebMvcSecurity
	@EnableAuthorizationServer
	protected static class AuthorizationServerExtras extends AuthorizationServerConfigurerAdapter implements Runnable {

		private TokenStore tokenStore = new InMemoryTokenStore();

		@Autowired
		private ApplicationContext context;

		@Override
		public void configure(OAuth2AuthorizationServerConfigurer oauthServer) throws Exception {
			oauthServer.tokenStore(tokenStore).realm("sparklr2/client");
		}

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			// @formatter:off
		 	clients.inMemory()
		        .withClient("my-trusted-client")
		            .authorizedGrantTypes("password", "authorization_code", "refresh_token", "implicit")
		            .authorities("ROLE_CLIENT", "ROLE_TRUSTED_CLIENT")
		            .scopes("read", "write", "trust")
		            .accessTokenValiditySeconds(60);
		 	// @formatter:on
		}

		@Override
		public void run() {
			assertNotNull(context.getBean("clientDetailsService", ClientDetailsService.class).loadClientByClientId(
					"my-trusted-client"));
			assertNotNull(ReflectionTestUtils.getField(context.getBean(AuthorizationEndpoint.class), "userApprovalHandler"));
		}

	}

	@Configuration
	@EnableWebMvcSecurity
	@EnableAuthorizationServer
	protected static class AuthorizationServerJdbc extends AuthorizationServerConfigurerAdapter {

		@Autowired
		private ApplicationContext context;

		@Override
		public void configure(OAuth2AuthorizationServerConfigurer oauthServer) throws Exception {
			oauthServer.tokenStore(new JdbcTokenStore(dataSource())).realm("sparklr2/client");
		}

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			// @formatter:off
		 	clients.jdbc(dataSource())
		        .withClient("my-trusted-client")
		            .authorizedGrantTypes("password", "authorization_code", "refresh_token", "implicit")
		            .authorities("ROLE_CLIENT", "ROLE_TRUSTED_CLIENT")
		            .scopes("read", "write", "trust")
		            .accessTokenValiditySeconds(60);
		 	// @formatter:on
		}

		@Bean
		public DataSource dataSource() {
			return Mockito.mock(DataSource.class);
		}

	}

	@Configuration
	@EnableWebMvcSecurity
	@EnableAuthorizationServer
	protected static class AuthorizationServerJwt extends AuthorizationServerConfigurerAdapter {

		@Autowired
		private ApplicationContext context;
		
		private JwtTokenServices tokenServices = new JwtTokenServices();

		@Override
		public void configure(OAuth2AuthorizationServerConfigurer oauthServer) throws Exception {
			oauthServer.tokenService(tokenServices).realm("sparklr2/client");
		}

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			// @formatter:off
		 	clients.inMemory()
		        .withClient("my-trusted-client")
		            .authorizedGrantTypes("password", "authorization_code", "refresh_token", "implicit")
		            .authorities("ROLE_CLIENT", "ROLE_TRUSTED_CLIENT")
		            .scopes("read", "write", "trust")
		            .accessTokenValiditySeconds(60);
		 	// @formatter:on
		}

	}

	@Configuration
	@EnableWebMvcSecurity
	@EnableAuthorizationServer
	protected static class AuthorizationServerApproval extends AuthorizationServerConfigurerAdapter implements Runnable {

		private TokenStore tokenStore = new InMemoryTokenStore();

		@Autowired
		private ApplicationContext context;
		
		@Override
		public void configure(OAuth2AuthorizationServerConfigurer oauthServer) throws Exception {
			oauthServer.tokenStore(tokenStore);
		}

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			// @formatter:off
		 	clients.inMemory()
		        .withClient("my-trusted-client")
		            .authorizedGrantTypes("password", "authorization_code", "refresh_token", "implicit")
		            .authorities("ROLE_CLIENT", "ROLE_TRUSTED_CLIENT")
		            .scopes("read", "write", "trust")
		            .accessTokenValiditySeconds(60);
		 	// @formatter:on
		}

		@Override
		public void run() {
			assertNotNull(ReflectionTestUtils.getField(context.getBean(AuthorizationEndpoint.class), "userApprovalHandler"));
		}

	}

	@Configuration
	@EnableWebMvcSecurity
	protected static class AuthorizationServerTypes extends AuthorizationServerConfiguration {

		// TODO: actually configure a token granter
		@Override
		protected void configure(OAuth2AuthorizationServerConfigurer oauthServer) throws Exception {
		}

	}

}
