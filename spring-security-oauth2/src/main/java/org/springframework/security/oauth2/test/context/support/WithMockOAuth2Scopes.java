/*
 * Copyright 2002-2014 the original author or authors.
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
package org.springframework.security.oauth2.test.context.support;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.test.context.support.WithSecurityContext;
import org.springframework.security.test.context.support.WithSecurityContextTestExecutionListener;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * When used with {@link WithSecurityContextTestExecutionListener} this annotation can be
 * added to a test method to emulate running with a mocked user. In order to work with
 * {@link MockMvc} The {@link SecurityContext} that is used will have the following
 * properties:
 *
 * <ul>
 * <li>The {@link SecurityContext} created will be that of
 * {@link SecurityContextHolder#createEmptyContext()}</li>
 * <li>It will be populated with an {@link OAuth2Authentication} that uses
 * the scopes provided in {@link #scopes()}.
 * </ul>
 *
 * @see WithMockOAuth2Scopes
 *
 * @author Michael Claassen
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@WithSecurityContext(factory = WithMockOAuth2ScopesSecurityContextFactory.class)
public @interface WithMockOAuth2Scopes {
    /**
     * The scopes to be used. The default is no scopes.
     * @return
     */
    String[] scopes() default {};
}
