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
import org.springframework.core.annotation.AnnotationUtils;

import java.util.ArrayList;
import java.util.List;

import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.MatcherAssert.assertThat;

public class WithMockOAuth2ScopesTests {

    @Test
    public void annotationWorks() {
        WithMockOAuth2Scopes withMockOAuth2Scopes = AnnotationUtils.findAnnotation(Annotated.class, WithMockOAuth2Scopes.class);

        List<String> scopes = new ArrayList<String>();

        for(String scope : withMockOAuth2Scopes.scopes()) {
            scopes.add(scope);
        }

        assertThat(scopes, hasItems("A", "B", "C"));
    }

    @WithMockOAuth2Scopes(scopes = {"A", "B", "C"})
    class Annotated {

    }
}
