/*
 * Copyright 2008 Web Cohesion
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

package org.springframework.security.oauth.provider;

import junit.framework.TestCase;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import static org.easymock.EasyMock.*;
import org.springframework.security.oauth.provider.token.OAuthProviderTokenServices;
import org.springframework.security.oauth.provider.token.OAuthProviderTokenImpl;
import org.springframework.security.oauth.provider.verifier.OAuthVerifierServices;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author Ryan Heaton
 */
public class TestOAuthUserAuthorizationProcessingFilter extends TestCase {

  /**
   * tests the attempt to authenticate.
   */
  public void testAttemptAuthentication() throws Exception {
    UserAuthorizationProcessingFilter filter = new UserAuthorizationProcessingFilter("/");
    OAuthVerifierServices vs = createMock(OAuthVerifierServices.class);
    filter.setVerifierServices(vs);
    HttpServletRequest request = createMock(HttpServletRequest.class);
    Authentication authentication = createMock(Authentication.class);
    OAuthProviderTokenServices tokenServices = createMock(OAuthProviderTokenServices.class);
    filter.setTokenServices(tokenServices);

    SecurityContextHolder.getContext().setAuthentication(authentication);
    expect(request.getParameter("requestToken")).andReturn("tok");
    OAuthProviderTokenImpl token = new OAuthProviderTokenImpl();
    token.setCallbackUrl("callback");
    expect(tokenServices.getToken("tok")).andReturn(token);
    request.setAttribute(UserAuthorizationProcessingFilter.CALLBACK_ATTRIBUTE, "callback");
    expect(authentication.isAuthenticated()).andReturn(false);
    replay(authentication, request, tokenServices, vs);
    try {
      filter.attemptAuthentication(request, createNiceMock(HttpServletResponse.class));
      fail();
    }
    catch (InsufficientAuthenticationException e) {
      verify(authentication, request, tokenServices, vs);
      reset(authentication, request, tokenServices, vs);
    }

    expect(authentication.isAuthenticated()).andReturn(true);
    expect(request.getParameter("requestToken")).andReturn("tok");
    expect(tokenServices.getToken("tok")).andReturn(token);
    request.setAttribute(UserAuthorizationProcessingFilter.CALLBACK_ATTRIBUTE, "callback");
    expect(vs.createVerifier()).andReturn("verifier");
    request.setAttribute(UserAuthorizationProcessingFilter.VERIFIER_ATTRIBUTE, "verifier");
    tokenServices.authorizeRequestToken("tok", "verifier", authentication);
    filter.setTokenServices(tokenServices);
    replay(authentication, request, tokenServices, vs);
    filter.attemptAuthentication(request, createNiceMock(HttpServletResponse.class));
    verify(authentication, request, tokenServices, vs);
    reset(authentication, request, tokenServices, vs);

    SecurityContextHolder.getContext().setAuthentication(null);
  }


}
