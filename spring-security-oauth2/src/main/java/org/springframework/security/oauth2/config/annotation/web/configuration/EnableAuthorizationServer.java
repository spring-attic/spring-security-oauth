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

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint;
import org.springframework.web.servlet.DispatcherServlet;

/**
 * Convenience annotation for enabling an Authorization Server (i.e. an {@link AuthorizationEndpoint} and a
 * {@link TokenEndpoint}) in the current application context, which must be a {@link DispatcherServlet} context. Many
 * features of the server can be customized using <code>@Beans</code> of type {@link AuthorizationServerConfigurer}
 * (e.g. by extending {@link AuthorizationServerConfigurerAdapter}). The user is responsible for securing the
 * Authorization Endpoint (/oauth/authorize) using normal Spring Security features ({@link EnableWebSecurity
 * &#064;EnableWebSecurity} etc.), but the Token Endpoint (/oauth/token) will be automatically secured using HTTP Basic
 * authentication on the client's credentials. Clients <em>must</em> be registered by providing a
 * {@link ClientDetailsService} through one or more AuthorizationServerConfigurers.
 * 
 * @author Dave Syer
 * 
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import({AuthorizationServerEndpointsConfiguration.class, AuthorizationServerSecurityConfiguration.class})
public @interface EnableAuthorizationServer {

}
