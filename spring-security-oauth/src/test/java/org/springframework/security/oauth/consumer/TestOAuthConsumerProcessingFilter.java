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

package org.springframework.security.oauth.consumer;

import junit.framework.TestCase;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.Authentication;
import static org.easymock.EasyMock.*;
import org.springframework.security.oauth.common.OAuthException;
import org.springframework.security.oauth.consumer.token.OAuthConsumerToken;
import org.springframework.security.oauth.consumer.token.OAuthConsumerTokenServices;
import org.springframework.security.oauth.consumer.token.OAuthConsumerTokenServicesFactory;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;

/**
 * @author Ryan Heaton
 */
public class TestOAuthConsumerProcessingFilter extends TestCase {

  @Override
  protected void tearDown() throws Exception {
    SecurityContextHolder.getContext().setAuthentication(null);
  }

  /**
   * tests the filter.
   */
  public void testDoFilter() throws Exception {
    HttpServletRequest request = createMock(HttpServletRequest.class);
    HttpServletResponse response = createMock(HttpServletResponse.class);
    FilterChain filterChain=createMock(FilterChain.class);
    final OAuthConsumerTokenServices tokenServices = createMock(OAuthConsumerTokenServices.class);
    final OAuthConsumerSupport support = createMock(OAuthConsumerSupport.class);
    OAuthConsumerProcessingFilter filter = new OAuthConsumerProcessingFilter() {
      @Override
      protected Set<String> getAccessTokenDependencies(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) {
        return new TreeSet<String>(Arrays.asList("dep1", "dep2", "dep3"));
      }

      @Override
      public OAuthConsumerTokenServicesFactory getTokenServicesFactory() {
        return new OAuthConsumerTokenServicesFactory() {
          public OAuthConsumerTokenServices getTokenServices(Authentication authentication, HttpServletRequest request) {
            return tokenServices;
          }
        };
      }

      @Override
      public OAuthConsumerSupport getConsumerSupport() {
        return support;
      }

      @Override
      protected String getCallbackURL(HttpServletRequest request) {
        return "urn:callback";
      }

      @Override
      protected String getUserAuthorizationRedirectURL(OAuthConsumerToken requestToken, String callbackURL) {
        return callbackURL + "&" + requestToken.getResourceId();
      }

      @Override
      protected void fail(HttpServletRequest request, HttpServletResponse response, OAuthException failure) throws IOException, ServletException {
        throw failure;
      }
    };

    Authentication authentication = createMock(Authentication.class);
    SecurityContextHolder.getContext().setAuthentication(authentication);
    expect(authentication.isAuthenticated()).andReturn(true);
    OAuthConsumerToken token1 = new OAuthConsumerToken();
    token1.setAccessToken(true);
    expect(tokenServices.getToken("dep1")).andReturn(token1);
    OAuthConsumerToken token2 = new OAuthConsumerToken();
    token2.setAccessToken(false);
    OAuthConsumerToken token2a = new OAuthConsumerToken();
    expect(tokenServices.getToken("dep2")).andReturn(token2);
    expect(request.getParameter("oauth_verifier")).andReturn("verifier");
    expect(support.getAccessToken(token2, "verifier")).andReturn(token2a);
    tokenServices.removeToken("dep2");
    tokenServices.storeToken("dep2", token2a);
    expect(tokenServices.getToken("dep3")).andReturn(null);
    OAuthConsumerToken token3 = new OAuthConsumerToken();
    token3.setResourceId("dep3");
    expect(support.getUnauthorizedRequestToken("dep3", "urn:callback?query")).andReturn(token3);
    tokenServices.storeToken("dep3", token3);
    expect(response.encodeRedirectURL("urn:callback")).andReturn("urn:callback?query");
    response.sendRedirect("urn:callback?query&dep3");

    replay(request, response, filterChain, tokenServices, support, authentication);
    filter.doFilter(request, response, filterChain);
    verify(request, response, filterChain, tokenServices, support, authentication);
    reset(request, response, filterChain, tokenServices, support, authentication);

    expect(authentication.isAuthenticated()).andReturn(false);
    replay(request, response, filterChain, tokenServices, support, authentication);
    try {
      filter.doFilter(request, response, filterChain);
      fail("should have required authentication");
    }
    catch (InsufficientAuthenticationException e) {
      verify(request, response, filterChain, tokenServices, support, authentication);
      reset(request, response, filterChain, tokenServices, support, authentication);
    }

    SecurityContextHolder.getContext().setAuthentication(authentication);
    expect(authentication.isAuthenticated()).andReturn(true);
    token1 = new OAuthConsumerToken();
    token1.setAccessToken(true);
    expect(tokenServices.getToken("dep1")).andReturn(token1);
    token2 = new OAuthConsumerToken();
    token2.setAccessToken(true);
    expect(tokenServices.getToken("dep2")).andReturn(token2);
    token3 = new OAuthConsumerToken();
    token3.setAccessToken(true);
    expect(tokenServices.getToken("dep3")).andReturn(token3);
    request.setAttribute(OAuthConsumerProcessingFilter.ACCESS_TOKENS_DEFAULT_ATTRIBUTE, new ArrayList(Arrays.asList(token1, token2, token3)));
    filterChain.doFilter(request, response);

    replay(request, response, filterChain, tokenServices, support, authentication);
    filter.doFilter(request, response, filterChain);
    verify(request, response, filterChain, tokenServices, support, authentication);
    reset(request, response, filterChain, tokenServices, support, authentication);
  }

  /**
   * tests getting the user authorization redirect URL.
   */
  public void testGetUserAuthorizationRedirectURL() throws Exception {
    final ProtectedResourceDetailsService detailsService = createMock(ProtectedResourceDetailsService.class);
    ProtectedResourceDetails details = createMock(ProtectedResourceDetails.class);
    OAuthConsumerProcessingFilter filter = new OAuthConsumerProcessingFilter() {
      @Override
      public ProtectedResourceDetailsService getProtectedResourceDetailsService() {
        return detailsService;
      }
    };

    OAuthConsumerToken token = new OAuthConsumerToken();
    token.setResourceId("resourceId");
    token.setValue("mytoken");
    expect(detailsService.loadProtectedResourceDetailsById("resourceId")).andReturn(details);
    expect(details.getUserAuthorizationURL()).andReturn("http://user-auth/context?with=some&queryParams");
    expect(details.isUse10a()).andReturn(false);
    replay(detailsService, details);
    assertEquals("http://user-auth/context?with=some&queryParams&oauth_token=mytoken&oauth_callback=urn%3A%2F%2Fcallback%3Fwith%3Dsome%26query%3Dparams",
                 filter.getUserAuthorizationRedirectURL(token, "urn://callback?with=some&query=params"));
    verify(detailsService, details);
    reset(detailsService, details);
    expect(detailsService.loadProtectedResourceDetailsById("resourceId")).andReturn(details);
    expect(details.getUserAuthorizationURL()).andReturn("http://user-auth/context?with=some&queryParams");
    expect(details.isUse10a()).andReturn(true);
    replay(detailsService, details);
    assertEquals("http://user-auth/context?with=some&queryParams&oauth_token=mytoken",
                 filter.getUserAuthorizationRedirectURL(token, "urn://callback?with=some&query=params"));
    verify(detailsService, details);
    reset(detailsService, details);
  }

}
