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
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * Convenient annotation for OAuth2 Resource Servers, enabling a Spring Security filter that authenticates requests via
 * an incoming OAuth2 token. Users should add this annotation and provide a <code>@Bean</code> of type
 * {@link ResourceServerConfigurer} (e.g. via {@link ResourceServerConfigurerAdapter}) that specifies the details of the
 * resource (URL paths and resource id). In order to use this filter you must {@link EnableWebSecurity
 * &#064;EnableWebSecurity} somewhere in your application, either in the same place as you use this annotation, or
 * somewhere else.
 * 
 * <p>
 * The annotation creates a {@link WebSecurityConfigurerAdapter} with a hard-coded {@link Order} (of 3). It's not
 * possible to change the order right now owing to technical limitations in Spring, so you must avoid using order=3 in
 * other WebSecurityConfigurerAdapters in your application (Spring Security will let you know if you forget).
 * 
 * @author Dave Syer
 * 
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(ResourceServerConfiguration.class)
public @interface EnableResourceServer {

}
