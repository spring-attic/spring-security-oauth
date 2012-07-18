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


package org.springframework.security.oauth2.provider.endpoint;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.stereotype.Component;

/**
 * <p>Synonym for &#64;Controller but only used for endpoints provided by the framework (so it never clashes with user's
 * own endpoints defined with &#64;Controller). Use with &#64;RequestMapping and all the other &#64;Controller features
 * (and match with a {@link FrameworkEndpointHandlerMapping} in the servlet context).</p>
 * 
 * <p>
 * Users of the Spring Security OAuth2 XSD namespace need not use this feature explicitly as the relevant handlers will
 * be registered by the parsers.
 * </p>
 * 
 * @author Dave Syer
 * 
 */
@Component
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface FrameworkEndpoint {

}
