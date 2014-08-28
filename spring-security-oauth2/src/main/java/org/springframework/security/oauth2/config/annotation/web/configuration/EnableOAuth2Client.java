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
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.web.filter.DelegatingFilterProxy;

/**
 * Enable configuration for an OAuth2 client in a web application that uses Spring Security and wants to use the
 * Authorization Code Grant from one or more OAuth2 Authorization servers. To take advantage of this feature you need a
 * global servlet filter in your application of the {@link DelegatingFilterProxy} that delegates to a bean named
 * "oauth2ClientContextFilter". Once that filter is in place your client app can use another bean provided by this
 * annotation (an {@link AccessTokenRequest}) to create an {@link OAuth2RestTemplate}, e.g.
 * 
 * <pre>
 * &#064;Configuration
 * &#064;EnableOAuth2Client
 * public class RemoteResourceConfiguration {
 * 
 * 	&#064;Bean
 *  public OAuth2RestOperations restTemplate(OAuth2ClientContext oauth2ClientContext) {
 * 		return new OAuth2RestTemplate(remote(), oauth2ClientContext);
 * 	}
 * 
 * }
 * </pre>
 * 
 * Client apps that use client credentials grants do not need the AccessTokenRequest or the scoped RestOperations (the
 * state is global for the app), but they should still use the filter to trigger the OAuth2RestOperations to obtain a
 * token when necessary. Apps that us password grants need to set the authentication properties in the
 * OAuth2ProtectedResourceDetails before using the RestOperations, and this means the resource details themselves also
 * have to be per session (assuming there are multiple users in the system).
 * 
 * @author Dave Syer
 * 
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(OAuth2ClientConfiguration.class)
public @interface EnableOAuth2Client {

}
