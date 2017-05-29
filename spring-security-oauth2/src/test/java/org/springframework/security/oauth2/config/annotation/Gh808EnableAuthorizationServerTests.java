/*
 * Copyright 2012-2016 the original author or authors.
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
package org.springframework.security.oauth2.config.annotation;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * gh-808
 * 
 * @author Joe Grandja
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
@WebAppConfiguration
public class Gh808EnableAuthorizationServerTests {
	private static final String CLIENT_ID = "acme";
	private static final String CLIENT_SECRET = "acmesecret";
	private static final String USER_ID = CLIENT_ID;
	private static final String USER_SECRET = CLIENT_SECRET + "2";
	private static BaseClientDetails client;
	private static UserDetails user;

	@Autowired
	WebApplicationContext context;

	@Autowired
	FilterChainProxy springSecurityFilterChain;

	MockMvc mockMvc;

	static {
		client = new BaseClientDetails(CLIENT_ID, null, "read,write", "password,client_credentials", "ROLE_ADMIN", "http://example.com/oauth2callback");
		client.setClientSecret(CLIENT_SECRET);
		user = new User(USER_ID, USER_SECRET, Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")));
	}

	@Before
	public void setup() {
		mockMvc = MockMvcBuilders.webAppContextSetup(context).addFilters(springSecurityFilterChain).build();
	}

	@Test
	public void clientAuthenticationFailsUsingUserCredentialsOnClientCredentialsGrantFlow() throws Exception {
		mockMvc.perform(post("/oauth/token")
				.param("grant_type", "client_credentials")
				.header("Authorization", httpBasicCredentials(USER_ID, USER_SECRET)))
				.andExpect(status().isUnauthorized());
	}

	@Test
	public void clientAuthenticationFailsUsingUserCredentialsOnResourceOwnerPasswordGrantFlow() throws Exception {
		mockMvc.perform(post("/oauth/token")
				.param("grant_type", "password")
				.param("client_id", CLIENT_ID)
				.param("username", USER_ID)
				.param("password", USER_SECRET)
				.header("Authorization", httpBasicCredentials(USER_ID, USER_SECRET)))
				.andExpect(status().isUnauthorized());
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

		@Autowired
		@Qualifier("authenticationManagerBean")
		private AuthenticationManager authenticationManager;

		@Autowired
		private UserDetailsService userDetailsService;

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			clients.withClientDetails(clientDetailsService());
		}

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			endpoints
				.authenticationManager(this.authenticationManager)
					.userDetailsService(this.userDetailsService);
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

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth
					.userDetailsService(userDetailsService());
		}

		@Bean
		@Override
		public AuthenticationManager authenticationManagerBean() throws Exception {
			// Expose the Global AuthenticationManager
			return super.authenticationManagerBean();
		}

		@Bean
		public UserDetailsService userDetailsService() {
			return new UserDetailsService() {
				@Override
				public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
					return user;
				}
			};
		}
	}
}
