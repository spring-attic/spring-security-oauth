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
package org.springframework.security.oauth.examples.sparklr.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity.IgnoredRequestConfigurer;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth.examples.sparklr.mvc.AdminController;
import org.springframework.security.oauth.examples.sparklr.oauth.SparklrUserApprovalHandler;
import org.springframework.security.oauth2.config.annotation.authentication.configurers.InMemoryClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.OAuth2AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.expression.OAuth2WebSecurityExpressionHandler;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.security.oauth2.provider.token.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 * @author Rob Winch
 * 
 */
@Configuration
@Order(3)
public class OAuth2ServerConfig extends WebSecurityConfigurerAdapter {

	private static final String SPARKLR_RESOURCE_ID = "sparklr";

	@Autowired
	private TokenStore tokenStore;

	@Override
	public void configure(WebSecurity builder) throws Exception {
		IgnoredRequestConfigurer ignoring = builder.ignoring();
		ignoring.antMatchers("/oauth/uncache_approvals", "/oauth/cache_approvals");
	}

    @Bean
    public AdminController adminController(TokenStore tokenStore, ConsumerTokenServices tokenServices, SparklrUserApprovalHandler userApprovalHandler) {
        AdminController adminController = new AdminController();
        adminController.setTokenStore(tokenStore);
        adminController.setTokenServices(tokenServices);
        adminController.setUserApprovalHandler(userApprovalHandler);
        return adminController;
    }

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
        http
            .authorizeRequests()
                .expressionHandler(new OAuth2WebSecurityExpressionHandler())
                .antMatchers("/photos").access("#oauth2.denyOAuthClient() and hasRole('ROLE_USER') or #oauth2.hasScope('read')")
                .antMatchers("/photos/trusted/**").access("#oauth2.denyOAuthClient() and hasRole('ROLE_USER') or #oauth2.hasScope('trust')")
                .antMatchers("/photos/user/**").access("#oauth2.denyOAuthClient() and hasRole('ROLE_USER') or #oauth2.hasScope('trust')")
                .antMatchers("/photos/**").access("#oauth2.denyOAuthClient() and hasRole('ROLE_USER') or #oauth2.hasScope('read')")
	            .regexMatchers(HttpMethod.DELETE, "/oauth/users/([^/].*?)/tokens/.*")
	                .access("#oauth2.clientHasRole('ROLE_CLIENT') and (hasRole('ROLE_USER') or #oauth2.isClient()) and #oauth2.hasScope('write')")
	            .regexMatchers(HttpMethod.GET, "/oauth/users/.*")
	                .access("#oauth2.clientHasRole('ROLE_CLIENT') and (hasRole('ROLE_USER') or #oauth2.isClient()) and #oauth2.hasScope('read')")
	            .regexMatchers(HttpMethod.GET, "/oauth/clients/.*")
	                .access("#oauth2.clientHasRole('ROLE_CLIENT') and #oauth2.isClient() and #oauth2.hasScope('read')")
                .and()
            .requestMatchers()
                .antMatchers("/photos/**", "/oauth/users/**", "/oauth/clients/**")
                .and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER)
                .and()
            .exceptionHandling().accessDeniedHandler(new OAuth2AccessDeniedHandler())
                .and()
            // CSRF protection is awkward for machine clients
            .csrf()
                .requireCsrfProtectionMatcher(new AntPathRequestMatcher("/oauth/**")).disable()
            .apply(new OAuth2ResourceServerConfigurer()).tokenStore(tokenStore)
                .resourceId(SPARKLR_RESOURCE_ID);
    	// @formatter:on
	}

	@Configuration
	@Order(1)
	protected static class AuthorizationServerConfiguration extends OAuth2AuthorizationServerConfigurerAdapter {

		private TokenStore tokenStore = new InMemoryTokenStore();

		@Autowired
		private OAuth2RequestFactory requestFactory;

		@Autowired
		@Qualifier("authenticationManagerBean")
		private AuthenticationManager authenticationManager;

		@Autowired
		private ClientDetailsService clientDetailsService;

		@Value("${tonr.redirect:http://localhost:8080/tonr2/sparklr/redirect}")
		private String tonrRedirectUri;

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {

			// @formatter:off
			 	auth.apply(new InMemoryClientDetailsServiceConfigurer())
			 		.withClient("tonr")
			 			.resourceIds(SPARKLR_RESOURCE_ID)
			 			.authorizedGrantTypes("authorization_code", "implicit")
			 			.authorities("ROLE_CLIENT")
			 			.scopes("read", "write")
			 			.secret("secret")
			 		.and()
			 		.withClient("tonr-with-redirect")
			 			.resourceIds(SPARKLR_RESOURCE_ID)
			 			.authorizedGrantTypes("authorization_code", "implicit")
			 			.authorities("ROLE_CLIENT")
			 			.scopes("read", "write")
			 			.secret("secret")
			 			.redirectUris(tonrRedirectUri)
			 		.and()
		 		    .withClient("my-client-with-registered-redirect")
	 			        .resourceIds(SPARKLR_RESOURCE_ID)
	 			        .authorizedGrantTypes("authorization_code", "client_credentials")
	 			        .authorities("ROLE_CLIENT")
	 			        .scopes("read", "trust")
	 			        .redirectUris("http://anywhere?key=value")
		 		    .and()
	 		        .withClient("my-trusted-client")
 			            .authorizedGrantTypes("password", "authorization_code", "refresh_token", "implicit")
 			            .authorities("ROLE_CLIENT", "ROLE_TRUSTED_CLIENT")
 			            .scopes("read", "write", "trust")
 			            .accessTokenValiditySeconds(60)
		 		    .and()
	 		        .withClient("my-trusted-client-with-secret")
 			            .authorizedGrantTypes("password", "authorization_code", "refresh_token", "implicit")
 			            .authorities("ROLE_CLIENT", "ROLE_TRUSTED_CLIENT")
 			            .scopes("read", "write", "trust")
 			            .secret("somesecret")
	 		        .and()
 		            .withClient("my-less-trusted-client")
			            .authorizedGrantTypes("authorization_code", "implicit")
			            .authorities("ROLE_CLIENT")
			            .scopes("read", "write", "trust")
     		        .and()
		            .withClient("my-less-trusted-autoapprove-client")
		                .authorizedGrantTypes("implicit")
		                .authorities("ROLE_CLIENT")
		                .scopes("read", "write", "trust")
		                .autoApprove(true);
			// @formatter:on
		}

		@Bean
		@Override
		@Lazy
		@Scope(proxyMode=ScopedProxyMode.TARGET_CLASS)
		public SparklrUserApprovalHandler userApprovalHandler() throws Exception {
			SparklrUserApprovalHandler handler = new SparklrUserApprovalHandler();
			handler.setApprovalStore(approvalStore());
			handler.setRequestFactory(requestFactory);
			handler.setClientDetailsService(clientDetailsService);
			handler.setUseApprovalStore(true);
			return handler;
		}

		@Bean
		public ApprovalStore approvalStore() throws Exception {
			TokenApprovalStore store = new TokenApprovalStore();
			store.setTokenStore(tokenStore);
			return store;
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
	        http
	            .authorizeRequests()
	                .antMatchers("/oauth/token").fullyAuthenticated()
	                .and()
	            .requestMatchers()
                    .antMatchers("/oauth/token")
                    .and()
	            .apply(new OAuth2AuthorizationServerConfigurer())
	                .tokenStore(tokenStore)
	                .userApprovalHandler(userApprovalHandler())
	                .authenticationManager(authenticationManager)
	                .realm("sparklr2/client");
	    	// @formatter:on
		}

	}

}
