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

import org.junit.Test;
import org.junit.runners.model.Statement;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import java.util.Set;

import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class WithMockOAuth2ScopesRuleTests {

    boolean baseWasRun = false;

    @Test
    public void ruleWorks() throws Throwable {
        WithMockOAuth2ScopesRule rule = new WithMockOAuth2ScopesRule(new String[] {"A", "B", "C"});

        Statement base = new Statement() {
            @Override
            public void evaluate() throws Throwable {
                baseWasRun = true;
            }
        };

        rule.apply(base, null).evaluate();

        Set<String> scopes = ((OAuth2Authentication)SecurityContextHolder.getContext().getAuthentication()).getOAuth2Request().getScope();

        assertThat(scopes, hasItems("A", "B", "C"));
        assertThat(baseWasRun, is(true));
    }
}
