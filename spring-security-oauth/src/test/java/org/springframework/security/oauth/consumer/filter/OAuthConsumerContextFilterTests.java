package org.springframework.security.oauth.consumer.filter;

import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.anyObject;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.oauth.common.OAuthProviderParameter;
import org.springframework.security.oauth.consumer.AccessTokenRequiredException;
import org.springframework.security.oauth.consumer.BaseProtectedResourceDetails;
import org.springframework.security.oauth.consumer.OAuthConsumerSupport;
import org.springframework.security.oauth.consumer.OAuthConsumerToken;
import org.springframework.security.oauth.consumer.OAuthSecurityContextHolder;
import org.springframework.security.oauth.consumer.ProtectedResourceDetails;
import org.springframework.security.oauth.consumer.rememberme.NoOpOAuthRememberMeServices;
import org.springframework.security.oauth.consumer.rememberme.OAuthRememberMeServices;
import org.springframework.security.oauth.consumer.token.OAuthConsumerTokenServices;
import org.springframework.security.web.RedirectStrategy;

/**
 * @author Ryan Heaton
 */
@RunWith(MockitoJUnitRunner.class)
public class OAuthConsumerContextFilterTests {
	@Mock
	private ProtectedResourceDetails details;
	@Mock
	private HttpServletRequest request;
	@Mock
	private HttpServletResponse response;
	@Mock
	private FilterChain filterChain;
	@Mock
	private OAuthConsumerTokenServices tokenServices;
	@Mock
	private OAuthConsumerSupport support;

	/**
	 * tests getting the user authorization redirect URL.
	 */
	@Test
	public void testGetUserAuthorizationRedirectURL() throws Exception {
		OAuthConsumerContextFilter filter = new OAuthConsumerContextFilter();

		OAuthConsumerToken token = new OAuthConsumerToken();
		token.setResourceId("resourceId");
		token.setValue("mytoken");
		when(details.getUserAuthorizationURL()).thenReturn("http://user-auth/context?with=some&queryParams");
		when(details.isUse10a()).thenReturn(false);
		assertEquals(
				"http://user-auth/context?with=some&queryParams&oauth_token=mytoken&oauth_callback=urn%3A%2F%2Fcallback%3Fwith%3Dsome%26query%3Dparams",
				filter.getUserAuthorizationRedirectURL(details, token, "urn://callback?with=some&query=params"));

		when(details.getUserAuthorizationURL()).thenReturn("http://user-auth/context?with=some&queryParams");
		when(details.isUse10a()).thenReturn(true);
		assertEquals("http://user-auth/context?with=some&queryParams&oauth_token=mytoken",
				filter.getUserAuthorizationRedirectURL(details, token, "urn://callback?with=some&query=params"));
	}

	/**
	 * tests the filter.
	 */
	@Test
	public void testDoFilter() throws Exception {
		final OAuthRememberMeServices rememberMeServices = new NoOpOAuthRememberMeServices();
		final BaseProtectedResourceDetails resource = new BaseProtectedResourceDetails();
		resource.setId("dep1");

		OAuthConsumerContextFilter filter = new OAuthConsumerContextFilter() {
			@Override
			protected String getCallbackURL(HttpServletRequest request) {
				return "urn:callback";
			}

			@Override
			protected String getUserAuthorizationRedirectURL(ProtectedResourceDetails details,
					OAuthConsumerToken requestToken, String callbackURL) {
				return callbackURL + "&" + requestToken.getResourceId();
			}
		};
		filter.setRedirectStrategy(new RedirectStrategy() {
			public void sendRedirect(HttpServletRequest request, HttpServletResponse response, String url)
					throws IOException {
				response.sendRedirect(url);
			}
		});

		filter.setTokenServices(tokenServices);
		filter.setConsumerSupport(support);
		filter.setRememberMeServices(rememberMeServices);

		doThrow(new AccessTokenRequiredException(resource)).when(filterChain).doFilter(request, response);
		when(tokenServices.getToken("dep1")).thenReturn(null);
		when(request.getParameter("oauth_verifier")).thenReturn(null);
		when(response.encodeRedirectURL("urn:callback")).thenReturn("urn:callback?query");

		OAuthConsumerToken token = new OAuthConsumerToken();
		token.setAccessToken(false);
		token.setResourceId(resource.getId());
		when(support.getUnauthorizedRequestToken("dep1", "urn:callback?query")).thenReturn(token);

		filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(request, response);
		verify(tokenServices).storeToken("dep1", token);
		verify(response).sendRedirect("urn:callback?query&dep1");
		verify(request,times(2)).setAttribute(anyString(), anyObject());
		reset(request,response,filterChain);

		doThrow(new AccessTokenRequiredException(resource)).when(filterChain).doFilter(request, response);
		when(tokenServices.getToken("dep1")).thenReturn(token);
		when(request.getParameter(OAuthProviderParameter.oauth_verifier.toString())).thenReturn("verifier");
		OAuthConsumerToken accessToken = new OAuthConsumerToken();
		when(support.getAccessToken(token, "verifier")).thenReturn(accessToken);
		when(response.isCommitted()).thenReturn(false);

		filter.doFilter(request, response, filterChain);

		verify(filterChain,times(2)).doFilter(request, response);
		verify(tokenServices).removeToken("dep1");
		verify(tokenServices).storeToken("dep1", accessToken);
		verify(request,times(2)).setAttribute(anyString(), anyObject());
	}

	@After
	public void tearDown() throws Exception {
		OAuthSecurityContextHolder.setContext(null);
	}
}
