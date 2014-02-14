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

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.oauth.common.OAuthConsumerParameter;
import org.springframework.security.oauth.provider.filter.CoreOAuthProviderSupport;

/**
 * @author Ryan Heaton
 */
@RunWith(MockitoJUnitRunner.class)
public class CoreOAuthProviderSupportTests {
	@Mock
	private HttpServletRequest request;

	/**
	 * tests parsing parameters.
	 */
	@Test
	public void testParseParameters() throws Exception {
		CoreOAuthProviderSupport support = new CoreOAuthProviderSupport();
		when(request.getHeaders("Authorization")).thenReturn(
				Collections.enumeration(Arrays.asList("OAuth realm=\"http://sp.example.com/\",\n"
						+ "                oauth_consumer_key=\"0685bd9184jfhq22\",\n"
						+ "                oauth_token=\"ad180jjd733klru7\",\n"
						+ "                oauth_signature_method=\"HMAC-SHA1\",\n"
						+ "                oauth_signature=\"wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D\",\n"
						+ "                oauth_timestamp=\"137131200\",\n"
						+ "                oauth_nonce=\"4572616e48616d6d65724c61686176\",\n"
						+ "                oauth_version=\"1.0\"")));
		Map<String, String> params = support.parseParameters(request);
		assertEquals("http://sp.example.com/", params.get("realm"));
		assertEquals("0685bd9184jfhq22", params.get(OAuthConsumerParameter.oauth_consumer_key.toString()));
		assertEquals("ad180jjd733klru7", params.get(OAuthConsumerParameter.oauth_token.toString()));
		assertEquals("HMAC-SHA1", params.get(OAuthConsumerParameter.oauth_signature_method.toString()));
		assertEquals("wOJIO9A2W5mFwDgiDvZbTSMK/PY=", params.get(OAuthConsumerParameter.oauth_signature.toString()));
		assertEquals("137131200", params.get(OAuthConsumerParameter.oauth_timestamp.toString()));
		assertEquals("4572616e48616d6d65724c61686176", params.get(OAuthConsumerParameter.oauth_nonce.toString()));
		assertEquals("1.0", params.get(OAuthConsumerParameter.oauth_version.toString()));
	}

	/**
	 * tests getting the signature base string.
	 */
	@Test
	public void testGetSignatureBaseString() throws Exception {
		Map<String, String[]> requestParameters = new HashMap<String, String[]>();
		requestParameters.put("file", new String[] { "vacation.jpg" });
		requestParameters.put("size", new String[] { "original" });

		when(request.getParameterNames()).thenReturn(Collections.enumeration(requestParameters.keySet()));
		for (String key : requestParameters.keySet()) {
			when(request.getParameterValues(key)).thenReturn(requestParameters.get(key));
		}

		when(request.getHeaders("Authorization")).thenReturn(
				Collections.enumeration(Arrays.asList("OAuth realm=\"http://sp.example.com/\",\n"
						+ "                oauth_consumer_key=\"dpf43f3p2l4k3l03\",\n"
						+ "                oauth_token=\"nnch734d00sl2jdk\",\n"
						+ "                oauth_signature_method=\"HMAC-SHA1\",\n"
						+ "                oauth_signature=\"unimportantforthistest\",\n"
						+ "                oauth_timestamp=\"1191242096\",\n"
						+ "                oauth_nonce=\"kllo9940pd9333jh\",\n"
						+ "                oauth_version=\"1.0\"")));

		when(request.getMethod()).thenReturn("gEt");
		CoreOAuthProviderSupport support = new CoreOAuthProviderSupport();
		support.setBaseUrl("http://photos.example.net");
		when(request.getRequestURI()).thenReturn("photos");

		String baseString = support.getSignatureBaseString(request);
		assertEquals(
				"GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal",
				baseString);
	}

}
