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

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint;
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpointHandlerMapping;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint;
import org.springframework.security.oauth2.provider.endpoint.WhitelabelApprovalEndpoint;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.ConsumerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;

/**
 * @author Rob Winch
 * @author Dave Syer
 *
 */
@Configuration
public abstract class OAuth2AuthorizationServerConfigurerAdapter extends WebSecurityConfigurerAdapter {

    @Bean
    public AuthorizationEndpoint authorizationEndpoint() throws Exception {
        AuthorizationEndpoint authorizationEndpoint = new AuthorizationEndpoint();
        authorizationEndpoint.setTokenGranter(tokenGranter());
        authorizationEndpoint.setClientDetailsService(clientDetailsService());
        authorizationEndpoint.setAuthorizationCodeServices(authorizationCodeServices());
        authorizationEndpoint.setUserApprovalHandler(userApprovalHandler());
        authorizationEndpoint.setImplicitGrantService(authorizationServerConfigurer().getImplicitGrantService());
        return authorizationEndpoint;
    }

    @Bean
    @Lazy
    @Scope(proxyMode=ScopedProxyMode.INTERFACES)
    public ConsumerTokenServices consumerTokenServices() throws Exception {
        return authorizationServerConfigurer().getConsumerTokenServices();
    }

    @Bean
    public TokenEndpoint tokenEndpoint() throws Exception {
        TokenEndpoint tokenEndpoint = new TokenEndpoint();
        tokenEndpoint.setClientDetailsService(clientDetailsService());
        tokenEndpoint.setTokenGranter(tokenGranter());
        return tokenEndpoint;
    }

    @Bean
    @Lazy
    @Scope(proxyMode=ScopedProxyMode.INTERFACES)
    public OAuth2RequestFactory oauth2RequestFactory() throws Exception {
        return authorizationServerConfigurer().getOAuth2RequestFactory();
    }

    @Bean
    @Lazy
    @Scope(proxyMode=ScopedProxyMode.INTERFACES)
    public TokenStore tokenStore() throws Exception {
        return authorizationServerConfigurer().getTokenStore();
    }

    @Bean
	@Lazy
	@Scope(proxyMode=ScopedProxyMode.INTERFACES)
    public UserApprovalHandler userApprovalHandler() throws Exception {
        return authorizationServerConfigurer().getUserApprovalHandler();
    }

    protected AuthorizationServerTokenServices tokenServices() throws Exception {
        return authorizationServerConfigurer().getTokenServices();
    }

    @Bean
    public WhitelabelApprovalEndpoint approvalEndpoint() {
        return new WhitelabelApprovalEndpoint();
    }

    @Bean
    public FrameworkEndpointHandlerMapping endpointHandlerMapping() {
        return new FrameworkEndpointHandlerMapping();
    }

    @Bean
    @Lazy
    @Scope(proxyMode=ScopedProxyMode.INTERFACES)
    public ClientDetailsService clientDetailsService() throws Exception {
        return getHttp().getSharedObject(ClientDetailsService.class);
    }

    @Bean
    @Lazy
    @Scope(proxyMode=ScopedProxyMode.INTERFACES)
    public AuthorizationCodeServices authorizationCodeServices() throws Exception {
        return authorizationServerConfigurer().getAuthorizationCodeServices();
    }

    @Bean
    @Lazy
    @Scope(proxyMode=ScopedProxyMode.INTERFACES)
    public TokenGranter tokenGranter() throws Exception {
        return authorizationServerConfigurer().getTokenGranter();
    }

    private OAuth2AuthorizationServerConfigurer authorizationServerConfigurer() throws Exception {
        return getHttp().getConfigurer(OAuth2AuthorizationServerConfigurer.class);
    }
}
