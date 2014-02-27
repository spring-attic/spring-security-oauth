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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth.common.OAuthConsumerParameter;
import org.springframework.security.oauth.common.signature.OAuthSignatureMethod;
import org.springframework.security.oauth.common.signature.OAuthSignatureMethodFactory;
import org.springframework.security.oauth.common.signature.SignatureSecret;
import org.springframework.security.oauth.provider.ConsumerAuthentication;
import org.springframework.security.oauth.provider.ConsumerCredentials;
import org.springframework.security.oauth.provider.ConsumerDetails;
import org.springframework.security.oauth.provider.ConsumerDetailsService;
import org.springframework.security.oauth.provider.InvalidOAuthParametersException;
import org.springframework.security.oauth.provider.OAuthProviderSupport;
import org.springframework.security.oauth.provider.OAuthVersionUnsupportedException;
import org.springframework.security.oauth.provider.nonce.OAuthNonceServices;
import org.springframework.security.oauth.provider.token.OAuthProviderToken;
import org.springframework.security.oauth.provider.token.OAuthProviderTokenServices;

/**
 * Tests the basic processing filter logic.
 *
 * @author Ryan Heaton
 */
@RunWith(MockitoJUnitRunner.class)
public class OAuthProcessingFilterTests {
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

			protected void onValidSignature(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
					throws IOException, ServletException {
				chain.doFilter(null, null);
			}

			@Override
			protected void validateOAuthParams(ConsumerDetails consumerDetails, Map<String, String> oauthParams)
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
			protected void resetPreviousAuthentication(Authentication previousAuthentication) {
				// no-op
			}

			@Override
			protected boolean skipProcessing(HttpServletRequest request) {
				return false;
			}

		};


		filter.setProviderSupport(providerSupport);
		filter.setConsumerDetailsService(consumerDetailsService);
		filter.setNonceServices(nonceServices);
		filter.setSignatureMethodFactory(signatureFactory);
		filter.setTokenServices(tokenServices);

		when(request.getMethod()).thenReturn("DELETE");

		filter.doFilter(request, response, filterChain);

		verify(response).sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
		assertFalse(triggers[0]);
		assertFalse(triggers[1]);
		Arrays.fill(triggers, false);

		when(request.getMethod()).thenReturn("GET");
		HashMap<String, String> requestParams = new HashMap<String, String>();
		when(providerSupport.parseParameters(request)).thenReturn(requestParams);
		try {
			filter.doFilter(request, response, filterChain);
			fail("should have required a consumer key.");
		} catch (InvalidOAuthParametersException e) {
			assertFalse(triggers[0]);
			assertFalse(triggers[1]);
			Arrays.fill(triggers, false);
		}

		when(request.getMethod()).thenReturn("GET");
		requestParams = new HashMap<String, String>();
		requestParams.put(OAuthConsumerParameter.oauth_consumer_key.toString(), "consumerKey");
		when(providerSupport.parseParameters(request)).thenReturn(requestParams);
		ConsumerDetails consumerDetails = mock(ConsumerDetails.class);
		when(consumerDetails.getAuthorities()).thenReturn(new ArrayList<GrantedAuthority>());
		when(consumerDetailsService.loadConsumerByConsumerKey("consumerKey")).thenReturn(consumerDetails);
		requestParams.put(OAuthConsumerParameter.oauth_token.toString(), "tokenvalue");
		requestParams.put(OAuthConsumerParameter.oauth_signature_method.toString(), "methodvalue");
		requestParams.put(OAuthConsumerParameter.oauth_signature.toString(), "signaturevalue");
		when(providerSupport.getSignatureBaseString(request)).thenReturn("sigbasestring");

		filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(null, null);
		verify(request).setAttribute(OAuthProviderProcessingFilter.OAUTH_PROCESSING_HANDLED, Boolean.TRUE);
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

	/**
	 * tests validation of the params.
	 */
	@Test
	public void testValidateParams() throws Exception {
		OAuthProviderProcessingFilter filter = new OAuthProviderProcessingFilter() {

			protected void onValidSignature(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
					throws IOException, ServletException {
			}

		};

		ConsumerDetails consumerDetails = mock(ConsumerDetails.class);
		HashMap<String, String> params = new HashMap<String, String>();

		params.put(OAuthConsumerParameter.oauth_version.toString(), "1.1");
		try {
			filter.validateOAuthParams(consumerDetails, params);
			fail("should have thrown a bad credentials.");
		} catch (OAuthVersionUnsupportedException e) {
			params.remove(OAuthConsumerParameter.oauth_version.toString());
		}

		filter.getAuthenticationEntryPoint().setRealmName("anywho");
		params.put("realm", "hello");
		try {
			filter.validateOAuthParams(consumerDetails, params);
			fail("should have thrown a bad credentials.");
		} catch (InvalidOAuthParametersException e) {
		}

		params.put("realm", "anywho");
		try {
			filter.validateOAuthParams(consumerDetails, params);
			fail("should have thrown a bad credentials for missing signature method.");
		} catch (InvalidOAuthParametersException e) {
		}

		params.remove("realm");
		params.put(OAuthConsumerParameter.oauth_signature_method.toString(), "sigmethod");
		try {
			filter.validateOAuthParams(consumerDetails, params);
			fail("should have thrown a bad credentials for missing signature.");
		} catch (InvalidOAuthParametersException e) {
		}

		params.remove("realm");
		params.put(OAuthConsumerParameter.oauth_signature_method.toString(), "sigmethod");
		params.put(OAuthConsumerParameter.oauth_signature.toString(), "value");
		try {
			filter.validateOAuthParams(consumerDetails, params);
			fail("should have thrown a bad credentials for missing timestamp.");
		} catch (InvalidOAuthParametersException e) {
		}

		params.remove("realm");
		params.put(OAuthConsumerParameter.oauth_signature_method.toString(), "sigmethod");
		params.put(OAuthConsumerParameter.oauth_signature.toString(), "value");
		params.put(OAuthConsumerParameter.oauth_timestamp.toString(), "value");
		try {
			filter.validateOAuthParams(consumerDetails, params);
			fail("should have thrown a bad credentials for missing nonce.");
		} catch (InvalidOAuthParametersException e) {
		}

		params.remove("realm");
		params.put(OAuthConsumerParameter.oauth_signature_method.toString(), "sigmethod");
		params.put(OAuthConsumerParameter.oauth_signature.toString(), "value");
		params.put(OAuthConsumerParameter.oauth_timestamp.toString(), "value");
		params.put(OAuthConsumerParameter.oauth_nonce.toString(), "value");
		try {
			filter.validateOAuthParams(consumerDetails, params);
			fail("should have thrown a bad credentials for bad timestamp.");
		} catch (InvalidOAuthParametersException e) {
		}

		OAuthNonceServices nonceServices = mock(OAuthNonceServices.class);
		filter.setNonceServices(nonceServices);
		params.remove("realm");
		params.put(OAuthConsumerParameter.oauth_signature_method.toString(), "sigmethod");
		params.put(OAuthConsumerParameter.oauth_signature.toString(), "value");
		params.put(OAuthConsumerParameter.oauth_timestamp.toString(), "1111111");
		params.put(OAuthConsumerParameter.oauth_nonce.toString(), "value");

		filter.validateOAuthParams(consumerDetails, params);

		verify(nonceServices).validateNonce(consumerDetails, 1111111L, "value");
	}

	/**
	 * test validating the signature.
	 */
	@Test
	public void testValidateSignature() throws Exception {
		OAuthProviderProcessingFilter filter = new OAuthProviderProcessingFilter() {
			@Override
			protected void onValidSignature(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
					throws IOException, ServletException {
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
}