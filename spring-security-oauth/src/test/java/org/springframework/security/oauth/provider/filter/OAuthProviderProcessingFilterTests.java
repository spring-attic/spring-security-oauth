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

package org.springframework.security.oauth.provider.filter;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth.common.OAuthConstants;
import org.springframework.security.oauth.common.OAuthException;
import org.springframework.security.oauth.common.OAuthParameters;
import org.springframework.security.oauth.common.signature.OAuthSignatureMethod;
import org.springframework.security.oauth.common.signature.OAuthSignatureMethodFactory;
import org.springframework.security.oauth.common.signature.SignatureSecret;
import org.springframework.security.oauth.provider.*;
import org.springframework.security.oauth.provider.endpoint.FrameworkEndpointHandlerMapping;
import org.springframework.security.oauth.provider.nonce.OAuthNonceServices;
import org.springframework.security.oauth.provider.token.OAuthAccessProviderToken;
import org.springframework.security.oauth.provider.token.OAuthProviderToken;
import org.springframework.security.oauth.provider.token.OAuthProviderTokenServices;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/**
 * Tests the basic processing filter logic.
 *
 * @author Ryan Heaton
 * @author <a rel="author" href="http://autayeu.com/">Aliaksandr Autayeu</a>
 */
@RunWith ( MockitoJUnitRunner.class )
public class OAuthProviderProcessingFilterTests {
	@Mock
	private OAuthProviderSupport providerSupport;
	@Mock
	private ConsumerDetailsService consumerDetailsService;
	@Mock
	private OAuthNonceServices nonceServices;
	@Mock
	private OAuthSignatureMethodFactory signatureFactory;
	@Mock
	private OAuthProviderTokenServices tokenServices;
	@Mock
	private HttpServletRequest request;
	@Mock
	private HttpServletResponse response;
	@Mock
	private FilterChain filterChain;

	/**
	 * tests do filter.
	 */
	@Test
	public void testDoFilter() throws Exception {
		final boolean[] triggers = new boolean[2];
		Arrays.fill(triggers, false);
		OAuthProviderProcessingFilter filter = new OAuthProviderProcessingFilter() {

			@Override
			protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response,
													 FilterChain filterChain) {
				return true;
			}

			@Override
			protected void validateOAuthParams(ConsumerDetails consumerDetails, OAuthParameters oauthParams)
					throws InvalidOAuthParametersException {
				triggers[0] = true;
			}

			@Override
			protected void validateSignature(ConsumerAuthentication authentication) throws AuthenticationException {
				triggers[1] = true;
			}

			@Override
			protected void fail(HttpServletRequest request, HttpServletResponse response,
								AuthenticationException failure) throws IOException, ServletException {
				throw failure;
			}

			@Override
			protected Object createDetails(HttpServletRequest request, ConsumerDetails consumerDetails) {
				return null;
			}

			@Override
			protected void resetPreviousContext(SecurityContext previousContext) {
				// no-op
			}

			public boolean isIgnoreMissingCredentials() {
				return false;
			}

			@Override
			protected boolean parametersAreAdequate(OAuthParameters oauthParams) {
				return true;
			}

			@Override
			protected boolean isEndpointRequest(HttpServletRequest request) {
				return true;
			}
		};


		filter.setProviderSupport(providerSupport);
		filter.setConsumerDetailsService(consumerDetailsService);
		filter.setNonceServices(nonceServices);
		filter.setSignatureMethodFactory(signatureFactory);
		filter.setTokenServices(tokenServices);

		when(request.getMethod()).thenReturn("GET");
		OAuthParameters requestParams = new OAuthParameters();
		when(providerSupport.parseParameters(request)).thenReturn(requestParams);
		try {
			filter.doFilter(request, response, filterChain);
			fail("should have required a consumer key.");
		}
		catch (InvalidOAuthParametersException e) {
			assertFalse(triggers[0]);
			assertFalse(triggers[1]);
			Arrays.fill(triggers, false);
		}

		when(request.getMethod()).thenReturn("GET");
		requestParams = new OAuthParameters();
		requestParams.setConsumerKey("consumerKey");
		when(providerSupport.parseParameters(request)).thenReturn(requestParams);
		ConsumerDetails consumerDetails = mock(ConsumerDetails.class);
		when(consumerDetails.getAuthorities()).thenReturn(new ArrayList<GrantedAuthority>());
		when(consumerDetailsService.loadConsumerByConsumerKey("consumerKey")).thenReturn(consumerDetails);
		requestParams.setToken("tokenvalue");
		requestParams.setSignatureMethod("methodvalue");
		requestParams.setSignature("signaturevalue");
		when(providerSupport.getSignatureBaseString(request)).thenReturn("sigbasestring");

		filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(request, response);
		ConsumerAuthentication authentication = (ConsumerAuthentication) SecurityContextHolder.getContext()
				.getAuthentication();
		assertSame(consumerDetails, authentication.getConsumerDetails());
		assertEquals("tokenvalue", authentication.getConsumerCredentials().getToken());
		assertEquals("methodvalue", authentication.getConsumerCredentials().getSignatureMethod());
		assertEquals("signaturevalue", authentication.getConsumerCredentials().getSignature());
		assertEquals("sigbasestring", authentication.getConsumerCredentials().getSignatureBaseString());
		assertEquals("consumerKey", authentication.getConsumerCredentials().getConsumerKey());
		assertTrue(authentication.isSignatureValidated());
		SecurityContextHolder.getContext().setAuthentication(null);
		assertTrue(triggers[0]);
		assertTrue(triggers[1]);
		Arrays.fill(triggers, false);
	}

	@Test
	public void testDoFilterSkipAuthentication() throws Exception {
		final boolean[] triggers = new boolean[1];
		Arrays.fill(triggers, false);
		OAuthProviderProcessingFilter filter = new OAuthProviderProcessingFilter() {

			@Override
			protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response,
													 FilterChain filterChain) {
				return false;
			}

			@Override
			protected boolean parametersAreAdequate(OAuthParameters oauthParams) {
				triggers[0] = true;
				return true;
			}
		};

		filter.setProviderSupport(providerSupport);
		filter.setConsumerDetailsService(consumerDetailsService);
		filter.setNonceServices(nonceServices);
		filter.setSignatureMethodFactory(signatureFactory);
		filter.setTokenServices(tokenServices);

		filter.doFilter(request, response, filterChain);
		verify(filterChain).doFilter(request, response);
		assertFalse(triggers[0]);
	}

	@Test
	public void testDoFilterBadParams() throws Exception {
		final boolean[] triggers = new boolean[1];
		Arrays.fill(triggers, false);
		OAuthProviderProcessingFilter filter = new OAuthProviderProcessingFilter() {

			@Override
			protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response,
													 FilterChain filterChain) {
				return true;
			}

			@Override
			protected boolean parametersAreAdequate(OAuthParameters oauthParams) {
				return false;
			}

			@Override
			protected void validateOAuthParams(ConsumerDetails consumerDetails, OAuthParameters oauthParams) throws InvalidOAuthParametersException {
				triggers[0] = true;
			}

			@Override
			protected boolean isOAuthAuthenticatedEndpointRequest(HttpServletRequest request) {
				return false;
			}
		};

		filter.setProviderSupport(providerSupport);
		filter.setConsumerDetailsService(consumerDetailsService);
		filter.setNonceServices(nonceServices);
		filter.setSignatureMethodFactory(signatureFactory);
		filter.setTokenServices(tokenServices);

		filter.doFilter(request, response, filterChain);
		verify(filterChain).doFilter(request, response);
		assertFalse(triggers[0]);
	}

	@Test
	public void testDoFilterBadParamsNotIgnored() throws Exception {
		final boolean[] triggers = new boolean[3];
		Arrays.fill(triggers, false);
		OAuthProviderProcessingFilter filter = new OAuthProviderProcessingFilter() {

			@Override
			protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response,
													 FilterChain filterChain) {
				return true;
			}

			@Override
			protected boolean parametersAreAdequate(OAuthParameters oauthParams) {
				return false;
			}

			@Override
			public boolean isIgnoreMissingCredentials() {
				return triggers[1];
			}

			@Override
			protected boolean isOAuthAuthenticatedEndpointRequest(HttpServletRequest request) {
				return triggers[2];
			}

			@Override
			protected void validateOAuthParams(ConsumerDetails consumerDetails, OAuthParameters oauthParams) throws InvalidOAuthParametersException {
				triggers[0] = true;
			}
		};

		filter.setProviderSupport(providerSupport);
		filter.setConsumerDetailsService(consumerDetailsService);
		filter.setNonceServices(nonceServices);
		filter.setSignatureMethodFactory(signatureFactory);
		filter.setTokenServices(tokenServices);
		OAuthProcessingFilterEntryPoint entryPoint = mock(OAuthProcessingFilterEntryPoint.class);
		filter.setAuthenticationEntryPoint(entryPoint);

		filter.doFilter(request, response, filterChain);
		verify(entryPoint).commence(eq(request), eq(response), any(AuthenticationException.class));

		triggers[1] = true;
		triggers[2] = false;
		filter.doFilter(request, response, filterChain);
		verify(filterChain).doFilter(request, response);

		triggers[1] = true;
		triggers[2] = true;
		entryPoint = mock(OAuthProcessingFilterEntryPoint.class);
		filter.setAuthenticationEntryPoint(entryPoint);
		filter.doFilter(request, response, filterChain);
		verify(entryPoint).commence(eq(request), eq(response), any(AuthenticationException.class));
	}

	@Test
	public void testIsEndpointRequest() {
		OAuthProviderProcessingFilter filter = new OAuthProviderProcessingFilter();

		FrameworkEndpointHandlerMapping handlerMapping = mock(FrameworkEndpointHandlerMapping.class);
		filter.setFrameworkEndpointHandlerMapping(handlerMapping);

		when(handlerMapping.getPaths()).thenReturn(Collections.singleton(OAuthConstants.DEFAULT_ACCESS_TOKEN_URL));
		when(handlerMapping.getPath(OAuthConstants.DEFAULT_ACCESS_TOKEN_URL)).thenReturn(OAuthConstants.DEFAULT_ACCESS_TOKEN_URL);
		when(request.getRequestURI()).thenReturn("/tonr" + OAuthConstants.DEFAULT_ACCESS_TOKEN_URL + ";sessionID....");
		when(request.getContextPath()).thenReturn("/tonr");
		assertTrue(filter.isEndpointRequest(request));

		when(handlerMapping.getPaths()).thenReturn(Collections.singleton(OAuthConstants.DEFAULT_ACCESS_TOKEN_URL));
		when(handlerMapping.getPath(OAuthConstants.DEFAULT_ACCESS_TOKEN_URL)).thenReturn(OAuthConstants.DEFAULT_ACCESS_TOKEN_URL);
		when(request.getRequestURI()).thenReturn("/tonr/photos/1.jpg");
		when(request.getContextPath()).thenReturn("/tonr");
		assertFalse(filter.isEndpointRequest(request));

		when(handlerMapping.getPaths()).thenReturn(Collections.singleton(OAuthConstants.DEFAULT_ACCESS_TOKEN_URL));
		when(handlerMapping.getPath(OAuthConstants.DEFAULT_ACCESS_TOKEN_URL)).thenReturn(OAuthConstants.DEFAULT_ACCESS_TOKEN_URL);
		when(request.getRequestURI()).thenReturn(OAuthConstants.DEFAULT_ACCESS_TOKEN_URL);
		when(request.getContextPath()).thenReturn("");
		assertTrue(filter.isEndpointRequest(request));

		when(handlerMapping.getPaths()).thenReturn(Collections.singleton(OAuthConstants.DEFAULT_ACCESS_TOKEN_URL));
		when(handlerMapping.getPath(OAuthConstants.DEFAULT_ACCESS_TOKEN_URL)).thenReturn(OAuthConstants.DEFAULT_ACCESS_TOKEN_URL);
		when(request.getRequestURI()).thenReturn("/photos/1.jpg");
		when(request.getContextPath()).thenReturn("");
		assertFalse(filter.isEndpointRequest(request));
	}

	@Test
	public void testIsOAuthAuthenticatedEndpointRequest() {
		OAuthProviderProcessingFilter filter = new OAuthProviderProcessingFilter();

		FrameworkEndpointHandlerMapping handlerMapping = mock(FrameworkEndpointHandlerMapping.class);
		filter.setFrameworkEndpointHandlerMapping(handlerMapping);

		when(handlerMapping.getOAuthAuthenticatedPaths()).thenReturn(Collections.singleton(OAuthConstants.DEFAULT_ACCESS_TOKEN_URL));
		when(handlerMapping.getPath(OAuthConstants.DEFAULT_ACCESS_TOKEN_URL)).thenReturn(OAuthConstants.DEFAULT_ACCESS_TOKEN_URL);
		when(request.getRequestURI()).thenReturn("/tonr" + OAuthConstants.DEFAULT_ACCESS_TOKEN_URL);
		when(request.getContextPath()).thenReturn("/tonr");
		assertTrue(filter.isOAuthAuthenticatedEndpointRequest(request));

		when(handlerMapping.getOAuthAuthenticatedPaths()).thenReturn(Collections.singleton(OAuthConstants.DEFAULT_ACCESS_TOKEN_URL));
		when(handlerMapping.getPath(OAuthConstants.DEFAULT_ACCESS_TOKEN_URL)).thenReturn(OAuthConstants.DEFAULT_ACCESS_TOKEN_URL);
		when(request.getRequestURI()).thenReturn("/tonr/photos/1.jpg");
		when(request.getContextPath()).thenReturn("/tonr");
		assertFalse(filter.isOAuthAuthenticatedEndpointRequest(request));

		when(handlerMapping.getOAuthAuthenticatedPaths()).thenReturn(Collections.singleton(OAuthConstants.DEFAULT_ACCESS_TOKEN_URL));
		when(handlerMapping.getPath(OAuthConstants.DEFAULT_ACCESS_TOKEN_URL)).thenReturn(OAuthConstants.DEFAULT_ACCESS_TOKEN_URL);
		when(request.getRequestURI()).thenReturn(OAuthConstants.DEFAULT_ACCESS_TOKEN_URL);
		when(request.getContextPath()).thenReturn("");
		assertTrue(filter.isOAuthAuthenticatedEndpointRequest(request));

		when(handlerMapping.getOAuthAuthenticatedPaths()).thenReturn(Collections.singleton(OAuthConstants.DEFAULT_ACCESS_TOKEN_URL));
		when(handlerMapping.getPath(OAuthConstants.DEFAULT_ACCESS_TOKEN_URL)).thenReturn(OAuthConstants.DEFAULT_ACCESS_TOKEN_URL);
		when(request.getRequestURI()).thenReturn("/photos/1.jpg");
		when(request.getContextPath()).thenReturn("");
		assertFalse(filter.isOAuthAuthenticatedEndpointRequest(request));
	}

	@Test
	public void testFail() throws IOException, ServletException {
		OAuthProcessingFilterEntryPoint entryPoint = mock(OAuthProcessingFilterEntryPoint.class);

		OAuthProviderProcessingFilter filter = new OAuthProviderProcessingFilter();
		filter.setAuthenticationEntryPoint(entryPoint);
		Authentication authentication = mock(Authentication.class);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		AuthenticationException e = mock(AuthenticationException.class);

		filter.fail(request, response, e);
		verify(entryPoint).commence(request, response, e);
		assertNotEquals(authentication, SecurityContextHolder.getContext().getAuthentication());
		SecurityContextHolder.clearContext();
	}

	/**
	 * tests validation of the params.
	 */
	@Test
	public void testValidateParams() throws Exception {
		OAuthProviderProcessingFilter filter = new OAuthProviderProcessingFilter();

		ConsumerDetails consumerDetails = mock(ConsumerDetails.class);
		OAuthParameters params = new OAuthParameters();

		params.setVersion("1.1");
		try {
			filter.validateOAuthParams(consumerDetails, params);
			fail("should have thrown a bad credentials.");
		}
		catch (OAuthVersionUnsupportedException e) {
			params.setVersion(null);
		}

		filter.getAuthenticationEntryPoint().setRealmName("anywho");
		params.setRealm("hello");
		try {
			filter.validateOAuthParams(consumerDetails, params);
			fail("should have thrown a bad credentials.");
		}
		catch (InvalidOAuthParametersException e) {
			// no-op
		}

		params.setRealm("anywho");
		try {
			filter.validateOAuthParams(consumerDetails, params);
			fail("should have thrown a bad credentials for missing signature method.");
		}
		catch (InvalidOAuthParametersException e) {
			// no-op
		}

		params.setRealm(null);
		params.setSignatureMethod("sigmethod");
		try {
			filter.validateOAuthParams(consumerDetails, params);
			fail("should have thrown a bad credentials for missing signature.");
		}
		catch (InvalidOAuthParametersException e) {
			// no-op
		}

		params.setRealm(null);
		params.setSignatureMethod("sigmethod");
		params.setSignature("value");
		try {
			filter.validateOAuthParams(consumerDetails, params);
			fail("should have thrown a bad credentials for missing timestamp.");
		}
		catch (InvalidOAuthParametersException e) {
			// no-op
		}

		params.setRealm(null);
		params.setSignatureMethod("sigmethod");
		params.setSignature("value");
		params.setTimestamp("value");
		try {
			filter.validateOAuthParams(consumerDetails, params);
			fail("should have thrown a bad credentials for missing nonce.");
		}
		catch (InvalidOAuthParametersException e) {
			// no-op
		}

		params.setRealm(null);
		params.setSignatureMethod("sigmethod");
		params.setSignature("value");
		params.setTimestamp("value");
		params.setNonce("value");
		try {
			filter.validateOAuthParams(consumerDetails, params);
			fail("should have thrown a bad credentials for bad timestamp.");
		}
		catch (InvalidOAuthParametersException e) {
			// no-op
		}

		OAuthNonceServices nonceServices = mock(OAuthNonceServices.class);
		filter.setNonceServices(nonceServices);
		params.setRealm(null);
		params.setSignatureMethod("sigmethod");
		params.setSignature("value");
		params.setTimestamp("1111111");
		params.setNonce("value");

		filter.validateOAuthParams(consumerDetails, params);

		verify(nonceServices).validateNonce(consumerDetails, 1111111L, "value");
	}

	/**
	 * test validating the signature.
	 */
	@Test
	public void testValidateSignature() throws Exception {
		OAuthProviderProcessingFilter filter = new OAuthProviderProcessingFilter() {
			public boolean isIgnoreMissingCredentials() {
				return false;
			}
		};

		ConsumerDetails details = mock(ConsumerDetails.class);
		SignatureSecret secret = mock(SignatureSecret.class);
		OAuthProviderToken token = mock(OAuthProviderToken.class);
		OAuthSignatureMethod sigMethod = mock(OAuthSignatureMethod.class);

		ConsumerCredentials credentials = new ConsumerCredentials("id", "sig", "method", "base", "token");
		when(details.getAuthorities()).thenReturn(new ArrayList<GrantedAuthority>());
		when(details.getSignatureSecret()).thenReturn(secret);
		filter.setTokenServices(tokenServices);
		when(tokenServices.getToken("token")).thenReturn(token);
		filter.setSignatureMethodFactory(signatureFactory);
		when(token.getSecret()).thenReturn("shhh!!!");
		when(signatureFactory.getSignatureMethod("method", secret, "shhh!!!")).thenReturn(sigMethod);

		ConsumerAuthentication authentication = new ConsumerAuthentication(details, credentials);
		filter.validateSignature(authentication);

		verify(sigMethod).verify("base", "sig");
	}

	/**
	 * test user authentication for resource requests
	 */
	@Test
	public void testUserAuthentication() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		OAuthParameters parameters = mock(OAuthParameters.class);
		when(parameters.getConsumerKey()).thenReturn("key");
		when(parameters.getToken()).thenReturn("tok");
		final CoreOAuthProviderSupport support = mock(CoreOAuthProviderSupport.class);
		when(support.parseParameters(request)).thenReturn(parameters);

		OAuthProviderProcessingFilter filter = new OAuthProviderProcessingFilter() {
			@Override
			protected boolean isEndpointRequest(HttpServletRequest request) {
				return false;
			}

			@Override
			public ConsumerDetailsService getConsumerDetailsService() {
				return new InMemoryConsumerDetailsService() {
					@Override
					public ConsumerDetails loadConsumerByConsumerKey(String consumerKey) throws OAuthException {
						return new BaseConsumerDetails() {
							@Override
							public List<GrantedAuthority> getAuthorities() {
								return Collections.emptyList();
							}
						};
					}
				};
			}

			@Override
			public OAuthProviderSupport getProviderSupport() {
				return support;
			}

			@Override
			protected void validateOAuthParams(ConsumerDetails consumerDetails, OAuthParameters oauthParams) throws InvalidOAuthParametersException {
			}

			@Override
			protected void validateSignature(ConsumerAuthentication authentication) throws AuthenticationException {
			}
		};
		ConsumerCredentials creds = new ConsumerCredentials("key", "sig", "meth", "base", "tok");
		ConsumerAuthentication authentication = new ConsumerAuthentication(mock(ConsumerDetails.class), creds);
		authentication.setAuthenticated(true);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		OAuthProviderTokenServices tokenServices = mock(OAuthProviderTokenServices.class);
		OAuthAccessProviderToken token = mock(OAuthAccessProviderToken.class);
		filter.setTokenServices(tokenServices);

		when(tokenServices.getToken("tok")).thenReturn(token);
		when(token.isAccessToken()).thenReturn(true);
		final ConsumerAuthentication userAuthentication = mock(ConsumerAuthentication.class);
		when(token.getUserAuthentication()).thenReturn(userAuthentication);
		FilterChain chain = new MockFilterChain() {
			@Override
			public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
				assertSame(userAuthentication, SecurityContextHolder.getContext().getAuthentication());
			}
		};

		// positive case
		filter.doFilter(request, response, chain);

		// negative case - no token
		when(parameters.getToken()).thenReturn(null);
		creds = new ConsumerCredentials("key", "sig", "meth", "base", null);
		authentication = new ConsumerAuthentication(mock(ConsumerDetails.class), creds);
		authentication.setAuthenticated(true);
		SecurityContextHolder.getContext().setAuthentication(authentication);

		OAuthProcessingFilterEntryPoint entryPoint = mock(OAuthProcessingFilterEntryPoint.class);
		filter.setAuthenticationEntryPoint(entryPoint);

		filter.doFilter(request, response, chain);
		verify(entryPoint).commence(eq(request), eq(response), any(AuthenticationException.class));
		assertNotEquals(authentication, SecurityContextHolder.getContext().getAuthentication());

		// negative case - positive case - extra trust
		ExtraTrustConsumerDetails extraTrustConsumerDetails = mock(ExtraTrustConsumerDetails.class);
		when(userAuthentication.getConsumerDetails()).thenReturn(extraTrustConsumerDetails);
		when(extraTrustConsumerDetails.isRequiredToObtainAuthenticatedToken()).thenReturn(false);
		filter.doFilter(request, response, chain);

		when(userAuthentication.getConsumerDetails()).thenReturn(mock(ConsumerDetails.class));

		// negative case - no access token
		when(parameters.getToken()).thenReturn("tok");
		creds = new ConsumerCredentials("key", "sig", "meth", "base", "tok");
		authentication = new ConsumerAuthentication(mock(ConsumerDetails.class), creds);
		authentication.setAuthenticated(true);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		when(tokenServices.getToken("tok")).thenReturn(null);
		try {
			filter.doFilter(request, response, chain);
			fail("should have thrown AccessDeniedException");
		} catch (AccessDeniedException e) {
			// no-op
		}

		// negative case - token is not access
		when(tokenServices.getToken("tok")).thenReturn(token);
		when(token.isAccessToken()).thenReturn(false);
		try {
			filter.doFilter(request, response, chain);
			fail("should have thrown AccessDeniedException");
		} catch (AccessDeniedException e) {
			// no-op
		}

		// negative case - token is not access, auth should remain consumer instead of user
		OAuthProviderToken providerToken = mock(OAuthProviderToken.class);
		when(tokenServices.getToken("tok")).thenReturn(providerToken);
		when(providerToken.isAccessToken()).thenReturn(true);
		chain = new MockFilterChain() {
			@Override
			public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
				assertNotSame(userAuthentication, SecurityContextHolder.getContext().getAuthentication());
			}
		};
		filter.doFilter(request, response, chain);

		SecurityContextHolder.getContext().setAuthentication(null);
	}

}