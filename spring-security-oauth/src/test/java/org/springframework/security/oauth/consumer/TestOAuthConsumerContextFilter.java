package org.springframework.security.oauth.consumer;

import static org.easymock.EasyMock.*;

import junit.framework.TestCase;
import org.springframework.security.oauth.common.OAuthProviderParameter;
import org.springframework.security.oauth.consumer.rememberme.NoOpOAuthRememberMeServices;
import org.springframework.security.oauth.consumer.rememberme.OAuthRememberMeServices;
import org.springframework.security.oauth.consumer.token.OAuthConsumerToken;
import org.springframework.security.oauth.consumer.token.OAuthConsumerTokenServices;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author Ryan Heaton
 */
public class TestOAuthConsumerContextFilter extends TestCase {
  /**
   * tests getting the user authorization redirect URL.
   */
  public void testGetUserAuthorizationRedirectURL() throws Exception {
    ProtectedResourceDetails details = createMock(ProtectedResourceDetails.class);
    OAuthConsumerContextFilter filter = new OAuthConsumerContextFilter();

    OAuthConsumerToken token = new OAuthConsumerToken();
    token.setResourceId("resourceId");
    token.setValue("mytoken");
    expect(details.getUserAuthorizationURL()).andReturn("http://user-auth/context?with=some&queryParams");
    expect(details.isUse10a()).andReturn(false);
    replay(details);
    assertEquals("http://user-auth/context?with=some&queryParams&oauth_token=mytoken&oauth_callback=urn%3A%2F%2Fcallback%3Fwith%3Dsome%26query%3Dparams",
                 filter.getUserAuthorizationRedirectURL(details, token, "urn://callback?with=some&query=params"));
    verify(details);
    reset(details);
    expect(details.getUserAuthorizationURL()).andReturn("http://user-auth/context?with=some&queryParams");
    expect(details.isUse10a()).andReturn(true);
    replay(details);
    assertEquals("http://user-auth/context?with=some&queryParams&oauth_token=mytoken",
                 filter.getUserAuthorizationRedirectURL(details, token, "urn://callback?with=some&query=params"));
    verify(details);
    reset(details);
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
    final OAuthRememberMeServices rememberMeServices = new NoOpOAuthRememberMeServices();
    final BaseProtectedResourceDetails resource = new BaseProtectedResourceDetails();
    resource.setId("dep1");

    OAuthConsumerContextFilter filter = new OAuthConsumerContextFilter() {
      @Override
      protected String getCallbackURL(HttpServletRequest request) {
        return "urn:callback";
      }

      @Override
      protected String getUserAuthorizationRedirectURL(ProtectedResourceDetails details, OAuthConsumerToken requestToken, String callbackURL) {
        return callbackURL + "&" + requestToken.getResourceId();
      }
    };

    filter.setTokenServices(tokenServices);
    filter.setConsumerSupport(support);
    filter.setRememberMeServices(rememberMeServices);

    request.setAttribute((String) anyObject(), anyObject());
    filterChain.doFilter(request, response);
    expectLastCall().andThrow(new AccessTokenRequiredException(resource));
    expect(tokenServices.getToken("dep1")).andReturn(null);
    expect(request.getParameter("oauth_verifier")).andReturn(null);
    expect(response.encodeRedirectURL("urn:callback")).andReturn("urn:callback?query");

    OAuthConsumerToken token = new OAuthConsumerToken();
    token.setAccessToken(false);
    token.setResourceId(resource.getId());
    expect(support.getUnauthorizedRequestToken("dep1", "urn:callback?query")).andReturn(token);
    tokenServices.storeToken("dep1", token);
    response.sendRedirect("urn:callback?query&dep1");

    replay(request, response, filterChain, tokenServices, support);
    filter.doFilter(request, response, filterChain);
    verify(request, response, filterChain, tokenServices, support);
    reset(request, response, filterChain, tokenServices, support);

    request.setAttribute((String) anyObject(), anyObject());
    filterChain.doFilter(request, response);
    expectLastCall().andThrow(new AccessTokenRequiredException(resource));
    expect(tokenServices.getToken("dep1")).andReturn(token);
    expect(request.getParameter(OAuthProviderParameter.oauth_verifier.toString())).andReturn("verifier");
    OAuthConsumerToken accessToken = new OAuthConsumerToken();
    expect(support.getAccessToken(token, "verifier")).andReturn(accessToken);
    tokenServices.removeToken("dep1");
    tokenServices.storeToken("dep1", accessToken);
    expect(response.isCommitted()).andReturn(false);
    request.setAttribute((String) anyObject(), anyObject());
    filterChain.doFilter(request, response);
    
    replay(request, response, filterChain, tokenServices, support);
    filter.doFilter(request, response, filterChain);
    verify(request, response, filterChain, tokenServices, support);
    reset(request, response, filterChain, tokenServices, support);
  }

  @Override
  protected void tearDown() throws Exception {
    OAuthSecurityContextHolder.setContext(null);
  }
}
