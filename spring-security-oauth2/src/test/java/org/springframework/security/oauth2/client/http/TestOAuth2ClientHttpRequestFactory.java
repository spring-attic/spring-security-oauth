package org.springframework.security.oauth2.client.http;

import static org.junit.Assert.assertEquals;

import java.net.URI;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.client.context.OAuth2ClientContext;
import org.springframework.security.oauth2.client.context.OAuth2ClientContextHolder;
import org.springframework.security.oauth2.client.provider.BaseOAuth2ProtectedResourceDetails;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class TestOAuth2ClientHttpRequestFactory {

	private OAuth2ClientContext savedContext;

	@Before
	public void open() {
		savedContext = OAuth2ClientContextHolder.getContext();
	}

	@After
	public void close() {
		OAuth2ClientContextHolder.setContext(savedContext);
	}

	/**
	 * tests appendQueryParameter
	 */
	@Test
	public void testAppendQueryParameter() throws Exception {
		OAuth2ClientHttpRequestFactory fac = new OAuth2ClientHttpRequestFactory(new SimpleClientHttpRequestFactory(),
				new BaseOAuth2ProtectedResourceDetails());
		OAuth2AccessToken token = new OAuth2AccessToken();
		token.setValue("12345");
		URI appended = fac.appendQueryParameter(URI.create("https://graph.facebook.com/search?type=checkin"), token);
		assertEquals("https://graph.facebook.com/search?type=checkin&bearer_token=12345", appended.toString());
	}

	/**
	 * tests appendQueryParameter
	 */
	@Test
	public void testAppendQueryParameterWithNoExistingParameters() throws Exception {
		OAuth2ClientHttpRequestFactory fac = new OAuth2ClientHttpRequestFactory(new SimpleClientHttpRequestFactory(),
				new BaseOAuth2ProtectedResourceDetails());
		OAuth2AccessToken token = new OAuth2AccessToken();
		token.setValue("12345");
		URI appended = fac.appendQueryParameter(URI.create("https://graph.facebook.com/search"), token);
		assertEquals("https://graph.facebook.com/search?bearer_token=12345", appended.toString());
	}

	/**
	 * tests encoding of access token value
	 */
	@Test
	public void testDoubleEncodingOfParameterValue() throws Exception {
		OAuth2ClientHttpRequestFactory fac = new OAuth2ClientHttpRequestFactory(new SimpleClientHttpRequestFactory(),
				new BaseOAuth2ProtectedResourceDetails());
		OAuth2AccessToken token = new OAuth2AccessToken();
		token.setValue("1/qIxxx");
		URI appended = fac.appendQueryParameter(URI.create("https://graph.facebook.com/search"), token);
		assertEquals("https://graph.facebook.com/search?bearer_token=1%2FqIxxx", appended.toString());
	}

	/**
	 * tests URI with fragment value
	 */
	@Test
	public void testFragmentUri() throws Exception {
		OAuth2ClientHttpRequestFactory fac = new OAuth2ClientHttpRequestFactory(new SimpleClientHttpRequestFactory(),
				new BaseOAuth2ProtectedResourceDetails());
		OAuth2AccessToken token = new OAuth2AccessToken();
		token.setValue("1234");
		URI appended = fac.appendQueryParameter(URI.create("https://graph.facebook.com/search#foo"), token);
		assertEquals("https://graph.facebook.com/search?bearer_token=1234#foo", appended.toString());
	}

	/**
	 * tests encoding of access token value passed in protected requests ref: SECOAUTH-90
	 */
	@Test
	public void testDoubleEncodingOfAccessTokenValue() throws Exception {
		OAuth2ClientHttpRequestFactory fac = new OAuth2ClientHttpRequestFactory(new SimpleClientHttpRequestFactory(),
				new BaseOAuth2ProtectedResourceDetails());
		OAuth2AccessToken token = new OAuth2AccessToken();
		// try with fictitious token value with many characters to encode
		token.setValue("1 qI+x:y=z");
		// System.err.println(UriUtils.encodeQueryParam(token.getValue(), "UTF-8"));
		URI appended = fac.appendQueryParameter(URI.create("https://graph.facebook.com/search"), token);
		assertEquals("https://graph.facebook.com/search?bearer_token=1+qI%2Bx%3Ay%3Dz", appended.toString());
	}

}
