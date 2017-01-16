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

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.test.context.support.WithSecurityContextFactory;

import java.util.HashSet;
import java.util.Set;

/**
 * A {@link WithMockOAuth2ScopesSecurityContextFactory} that works with {@link WithMockOAuth2Scopes}.
 *
 * @author Michael Claassen
 *
 * @see WithMockOAuth2Scopes
 */
public final class WithMockOAuth2ScopesSecurityContextFactory implements WithSecurityContextFactory<WithMockOAuth2Scopes> {

    @Override
    public SecurityContext createSecurityContext(WithMockOAuth2Scopes mockOAuth2Scopes) {
        SecurityContext context = SecurityContextHolder.createEmptyContext();

        Set<String> scopes = new HashSet<String>();

        for(String scope : mockOAuth2Scopes.scopes()) {
            scopes.add(scope);
        }

        OAuth2Request request = new OAuth2Request(null, null, null, true, scopes, null, null, null, null);

        Authentication auth = new OAuth2Authentication(request, null);

        context.setAuthentication(auth);

        return context;
    }
}
