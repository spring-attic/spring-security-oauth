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

import static org.easymock.EasyMock.*;
import org.springframework.security.oauth.provider.token.OAuthProviderToken;
import org.springframework.security.oauth.provider.token.OAuthProviderTokenServices;
import org.springframework.security.oauth.provider.token.OAuthAccessProviderToken;
import org.springframework.security.oauth.common.OAuthConsumerParameter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.GrantedAuthority;

import junit.framework.TestCase;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.FilterChain;
import java.io.StringWriter;
import java.io.PrintWriter;
import java.util.TreeMap;
import java.util.ArrayList;

/**
 * @author Ryan Heaton
 */
public class TestUnauthenticatedRequestTokenProcessingFilter extends TestCase {

  /**
   * test onValidSignature
   */
  public void testOnValidSignature() throws Exception {
    final OAuthProviderToken authToken = createMock(OAuthProviderToken.class);
    UnauthenticatedRequestTokenProcessingFilter filter = new UnauthenticatedRequestTokenProcessingFilter() {
      @Override
      protected OAuthProviderToken createOAuthToken(ConsumerAuthentication authentication) {
        return authToken;
      }
    };
    HttpServletRequest request = createMock(HttpServletRequest.class);
    HttpServletResponse response = createMock(HttpServletResponse.class);
    FilterChain filterChain = createMock(FilterChain.class);
    ConsumerCredentials creds = new ConsumerCredentials("key", "sig", "meth", "base", "tok");
    ConsumerDetails consumerDetails = createMock(ConsumerDetails.class);

    expect(authToken.getConsumerKey()).andReturn("chi");
    expect(authToken.getValue()).andReturn("tokvalue");
    expect(authToken.getSecret()).andReturn("shhhhhh");
    expect(consumerDetails.getAuthorities()).andReturn(new ArrayList<GrantedAuthority>());
    expect(consumerDetails.getConsumerKey()).andReturn("chi");
    response.setContentType("text/plain;charset=utf-8");
    StringWriter writer = new StringWriter();
    expect(response.getWriter()).andReturn(new PrintWriter(writer));
    response.flushBuffer();
    replay(request, response, filterChain, authToken, consumerDetails);
    TreeMap<String, String> params = new TreeMap<String, String>();
    params.put(OAuthConsumerParameter.oauth_callback.toString(), "mycallback");
    ConsumerAuthentication authentication = new ConsumerAuthentication(consumerDetails, creds, params);
    authentication.setAuthenticated(true);
    SecurityContextHolder.getContext().setAuthentication(authentication);
    filter.onValidSignature(request, response, filterChain);
    assertEquals("oauth_token=tokvalue&oauth_token_secret=shhhhhh&oauth_callback_confirmed=true", writer.toString());
    verify(request, response, filterChain, authToken, consumerDetails);
    reset(request, response, filterChain, authToken, consumerDetails);

    SecurityContextHolder.getContext().setAuthentication(null);
  }

  /**
   * tests creating the oauth token.
   */
  public void testCreateOAuthToken() throws Exception {
    ConsumerDetails consumerDetails = createMock(ConsumerDetails.class);
    ConsumerCredentials creds = new ConsumerCredentials("key", "sig", "meth", "base", "tok");
    OAuthProviderTokenServices tokenServices = createMock(OAuthProviderTokenServices.class);
    OAuthAccessProviderToken token = createMock(OAuthAccessProviderToken.class);

    UnauthenticatedRequestTokenProcessingFilter filter = new UnauthenticatedRequestTokenProcessingFilter();
    filter.setTokenServices(tokenServices);

    expect(consumerDetails.getConsumerKey()).andReturn("chi");
    expect(consumerDetails.getAuthorities()).andReturn(new ArrayList<GrantedAuthority>());
    expect(tokenServices.createUnauthorizedRequestToken("chi", "callback")).andReturn(token);
    replay(consumerDetails, tokenServices, token);
    TreeMap<String, String> map = new TreeMap<String, String>();
    map.put(OAuthConsumerParameter.oauth_callback.toString(), "callback");
    ConsumerAuthentication authentication = new ConsumerAuthentication(consumerDetails, creds, map);
    assertSame(token, filter.createOAuthToken(authentication));
    verify(consumerDetails, tokenServices, token);
    reset(consumerDetails, tokenServices, token);
  }

}
