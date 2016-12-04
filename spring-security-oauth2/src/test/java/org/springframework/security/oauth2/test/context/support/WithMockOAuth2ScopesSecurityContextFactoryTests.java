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

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import java.util.Set;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.CoreMatchers.*;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class WithMockOAuth2ScopesSecurityContextFactoryTests {

    @Mock
    WithMockOAuth2Scopes withMockOAuth2Scopes;

    private WithMockOAuth2ScopesSecurityContextFactory factory;

    @Before
    public void setup() {
        factory = new WithMockOAuth2ScopesSecurityContextFactory();
    }

    @Test
    public void scopesWork() {
        when(withMockOAuth2Scopes.scopes()).thenReturn(new String[]{"A", "B", "C"});

        Set<String> scopes = ((OAuth2Authentication)factory.createSecurityContext(withMockOAuth2Scopes).getAuthentication()).getOAuth2Request().getScope();

        assertThat(scopes, hasItems("A", "B", "C"));
    }
}
