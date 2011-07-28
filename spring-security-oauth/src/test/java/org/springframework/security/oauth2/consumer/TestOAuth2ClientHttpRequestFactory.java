package org.springframework.security.oauth2.consumer;

import static org.junit.Assert.assertEquals;

import java.net.URI;

import org.junit.Test;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

/**
 * @author Ryan Heaton
 */
public class TestOAuth2ClientHttpRequestFactory {

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
		assertEquals("https://graph.facebook.com/search?type=checkin&oauth_token=12345", appended.toString());
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
		assertEquals("https://graph.facebook.com/search?oauth_token=12345", appended.toString());
	}

}
