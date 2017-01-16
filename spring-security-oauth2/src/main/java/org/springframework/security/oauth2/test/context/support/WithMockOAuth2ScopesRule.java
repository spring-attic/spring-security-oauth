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

import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

import java.util.HashSet;
import java.util.Set;

/**
 * When used with {@link org.junit.Rule} or {@link org.junit.ClassRule}
 * performs setup to run tests with a {@link SecurityContext} populated
 * with an {@link OAuth2Authentication} that uses the scopes provided in
 * the constructor.
 *
 * @author Michael Claassen
 */
public class WithMockOAuth2ScopesRule implements TestRule {

    private Set<String> scopes;

    public WithMockOAuth2ScopesRule(String[] scopes) {
        this.scopes = new HashSet<String>();

        for(String scope : scopes) {
            this.scopes.add(scope);
        }
    }

    @Override
    public Statement apply(final Statement base, Description description) {
        return new Statement() {
            @Override
            public void evaluate() throws Throwable {
                SecurityContext context = SecurityContextHolder.createEmptyContext();

                OAuth2Request request = new OAuth2Request(null, null, null, true, scopes, null, null, null, null);

                Authentication auth = new OAuth2Authentication(request, null);

                context.setAuthentication(auth);

                SecurityContextHolder.setContext(context);

                base.evaluate();
            }
        };
    }
}
