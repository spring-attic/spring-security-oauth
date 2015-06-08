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

import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.expression.OAuth2WebSecurityExpressionHandler;

/**
 * Configurer interface for <code>@EnableResourceServer</code> classes. Implement this interface to adjust the access
 * rules and paths that are protected by OAuth2 security. Applications may provide multiple instances of this interface,
 * and in general (like with other Security configurers), if more than one configures the same property, then the last
 * one wins. The configurers are sorted by {@link Order} before being applied.
 * 
 * @author Dave Syer
 * 
 */
public interface ResourceServerConfigurer {

	/**
	 * Add resource-server specific properties (like a resource id). The defaults should work for many applications, but
	 * you might want to change at least the resource id.
	 * 
	 * @param resources configurer for the resource server
	 * @throws Exception if there is a problem
	 */
	void configure(ResourceServerSecurityConfigurer resources) throws Exception;

	/**
	 * Use this to configure the access rules for secure resources. By default all resources <i>not</i> in "/oauth/**"
	 * are protected (but no specific rules about scopes are given, for instance). You also get an
	 * {@link OAuth2WebSecurityExpressionHandler} by default.
	 * 
	 * @param http the current http filter configuration
	 * @throws Exception if there is a problem
	 */
	void configure(HttpSecurity http) throws Exception;

}
