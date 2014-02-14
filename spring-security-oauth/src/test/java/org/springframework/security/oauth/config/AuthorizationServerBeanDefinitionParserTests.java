/*
 * Copyright 2012 SURFnet b.v.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth.config;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Field;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth.provider.filter.UserAuthorizationProcessingFilter;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.util.ReflectionUtils;

@ContextConfiguration
@RunWith(SpringJUnit4ClassRunner.class)
public class AuthorizationServerBeanDefinitionParserTests {

  @Autowired
  private UserAuthorizationProcessingFilter filter;

  @Test
  public void filterUsesConfiguredTokenParameterName() {
    assertEquals("Token parameter name should equal the configured parameter name",
        "myOverriddenTokenIdParam", filter.getTokenParameterName());
  }

  @Test
  public void filterUsesConfiguredFailureHandler() throws Exception {
    final Field failureHandlerField = AbstractAuthenticationProcessingFilter.class.getDeclaredField("failureHandler");
    ReflectionUtils.makeAccessible(failureHandlerField);
    AuthenticationFailureHandler failureHandler = (AuthenticationFailureHandler) ReflectionUtils.getField(failureHandlerField, filter);
    assertTrue("failure handler should be a simpleUrlFailureHandler", failureHandler instanceof SimpleUrlAuthenticationFailureHandler);

    final Field failureUrlField = SimpleUrlAuthenticationFailureHandler.class.getDeclaredField("defaultFailureUrl");
    ReflectionUtils.makeAccessible(failureUrlField);
    String failureUrl = (String) ReflectionUtils.getField(failureUrlField, failureHandler);
    assertEquals("failure URL should be the configured url", "/oauth/confirm_access", failureUrl);
  }
}
