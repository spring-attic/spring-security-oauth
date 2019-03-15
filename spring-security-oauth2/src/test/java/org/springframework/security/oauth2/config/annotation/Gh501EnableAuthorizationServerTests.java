/*
 * Copyright 2012-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.config.annotation;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.UnsupportedEncodingException;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * gh-501
 *
 * @author Joe Grandja
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
@WebAppConfiguration
public class Gh501EnableAuthorizationServerTests {
	private static final String CLIENT_ID = "client-1234";
	private static final String CLIENT_SECRET = "secret-1234";
	private static BaseClientDetails client;

	@Autowired
	WebApplicationContext context;

	@Autowired
	FilterChainProxy springSecurityFilterChain;

	MockMvc mockMvc;

	static {
		client = new BaseClientDetails(CLIENT_ID, null, "read,write", "client_credentials", null);
		client.setClientSecret(CLIENT_SECRET);
	}

	@Before
	public void setup() {
		mockMvc = MockMvcBuilders.webAppContextSetup(context).addFilters(springSecurityFilterChain).build();
	}

	@Test
	public void clientAuthenticationFailsThenCustomAuthenticationEntryPointCalled() throws Exception {
		mockMvc.perform(post("/oauth/token")
				.param("grant_type", "client_credentials")
				.header("Authorization", httpBasicCredentials(CLIENT_ID, "invalid-secret")))
				.andExpect(status().isUnauthorized());

		verify(AuthorizationServerConfig.authenticationEntryPoint).commence(
				any(HttpServletRequest.class), any(HttpServletResponse.class), any(AuthenticationException.class));
	}

	private String httpBasicCredentials(String userName, String password) {
		String headerValue = "Basic ";
		byte[] toEncode = null;
		try {
			toEncode = (userName + ":" + password).getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) { }
		headerValue += new String(Base64.encode(toEncode));
		return headerValue;
	}

	@Configuration
	@EnableAuthorizationServer
	@EnableWebMvc
	static class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
		private static AuthenticationEntryPoint authenticationEntryPoint = spy(new OAuth2AuthenticationEntryPoint());

		@Override
		public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
			security.authenticationEntryPoint(authenticationEntryPoint);
		}

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			clients.withClientDetails(clientDetailsService());
		}

		@Bean
		public ClientDetailsService clientDetailsService() {
			return new ClientDetailsService() {
				@Override
				public ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
					return client;
				}
			};
		}
	}

	@Configuration
	@EnableWebSecurity
	static class WebSecurityConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					.anyRequest().authenticated();
		}

		@Bean
		public PasswordEncoder passwordEncoder() {
			return NoOpPasswordEncoder.getInstance();
		}
	}
}
