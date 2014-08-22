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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.oauth.common.OAuthParameters;
import org.springframework.security.oauth.provider.filter.CoreOAuthProviderSupport;

import javax.servlet.http.HttpServletRequest;
import java.util.*;

import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

/**
 * @author Ryan Heaton
 * @author <a rel="author" href="http://autayeu.com/">Aliaksandr Autayeu</a>
 */
@RunWith ( MockitoJUnitRunner.class )
public class CoreOAuthProviderSupportTests {
	@Mock
	private HttpServletRequest request;

	/**
	 * tests parsing header parameters.
	 */
	@Test
	public void testParseHeaderParameters() throws Exception {
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
		OAuthParameters params = support.parseParameters(request);
		assertEquals("http://sp.example.com/", params.getRealm());
		assertEquals("0685bd9184jfhq22", params.getConsumerKey());
		assertEquals("ad180jjd733klru7", params.getToken());
		assertEquals("HMAC-SHA1", params.getSignatureMethod());
		assertEquals("wOJIO9A2W5mFwDgiDvZbTSMK/PY=", params.getSignature());
		assertEquals("137131200", params.getTimestamp());
		assertEquals("4572616e48616d6d65724c61686176", params.getNonce());
		assertEquals("1.0", params.getVersion());
	}

	@Test
	public void testParseRequestParameters() throws Exception {
		CoreOAuthProviderSupport support = new CoreOAuthProviderSupport();
		when(request.getHeaders("Authorization")).thenReturn(null);

		OAuthParameters params = support.parseParameters(request);
		assertNull(params.getRealm());
		assertNull(params.getConsumerKey());
		assertNull(params.getToken());
		assertNull(params.getSignatureMethod());
		assertNull(params.getSignature());
		assertNull(params.getTimestamp());
		assertNull(params.getNonce());
		assertNull(params.getVersion());

		when(request.getParameter("realm")).thenReturn("http://sp.example.com/");
		when(request.getParameter("oauth_consumer_key")).thenReturn("0685bd9184jfhq22");
		when(request.getParameter("oauth_token")).thenReturn("ad180jjd733klru7");
		when(request.getParameter("oauth_signature_method")).thenReturn("HMAC-SHA1");
		when(request.getParameter("oauth_signature")).thenReturn("wOJIO9A2W5mFwDgiDvZbTSMK/PY=");
		when(request.getParameter("oauth_timestamp")).thenReturn("137131200");
		when(request.getParameter("oauth_nonce")).thenReturn("4572616e48616d6d65724c61686176");
		when(request.getParameter("oauth_version")).thenReturn("1.0");
		when(request.getParameter("test")).thenReturn("test");
		when(request.getParameter("secret")).thenReturn("secret");

		params = support.parseParameters(request);

		assertNull(params.getRealm());
		assertEquals("0685bd9184jfhq22", params.getConsumerKey());
		assertEquals("ad180jjd733klru7", params.getToken());
		assertEquals("HMAC-SHA1", params.getSignatureMethod());
		assertEquals("wOJIO9A2W5mFwDgiDvZbTSMK/PY=", params.getSignature());
		assertEquals("137131200", params.getTimestamp());
		assertEquals("4572616e48616d6d65724c61686176", params.getNonce());
		assertEquals("1.0", params.getVersion());
		assertNull(params.getCallback());
		assertNull(params.getCallbackConfirmed());
		assertNull(params.getTokenSecret());
		assertNull(params.getVerifier());
	}

	/**
	 * tests getting the signature base string.
	 */
	@Test
	public void testGetSignatureBaseString() throws Exception {
		Map<String, String[]> requestParameters = new HashMap<String, String[]>();
		requestParameters.put("file", new String[]{"vacation.jpg"});
		requestParameters.put("size", new String[]{"original"});

		when(request.getParameterNames()).thenReturn(Collections.enumeration(requestParameters.keySet()));
		for (String key : requestParameters.keySet()) {
			when(request.getParameterValues(key)).thenReturn(requestParameters.get(key));
		}

		List<String> headers = Arrays.asList("OAuth realm=\"http://sp.example.com/\",\n"
											   + "                oauth_consumer_key=\"dpf43f3p2l4k3l03\",\n"
											   + "                oauth_token=\"nnch734d00sl2jdk\",\n"
											   + "                oauth_signature_method=\"HMAC-SHA1\",\n"
											   + "                oauth_signature=\"unimportantforthistest\",\n"
											   + "                oauth_timestamp=\"1191242096\",\n"
											   + "                oauth_nonce=\"kllo9940pd9333jh\",\n"
											   + "                oauth_version=\"1.0\"");
		when(request.getHeaders("Authorization")).thenReturn(Collections.enumeration(headers));

		when(request.getMethod()).thenReturn("gEt");
		CoreOAuthProviderSupport support = new CoreOAuthProviderSupport();
		support.setBaseUrl("http://photos.example.net");
		when(request.getRequestURI()).thenReturn("photos");

		String baseString = support.getSignatureBaseString(request);
		assertEquals(
				"GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal",
				baseString);


		// test non-standard port
		when(request.getHeaders("Authorization")).thenReturn(Collections.enumeration(headers));
		when(request.getMethod()).thenReturn("gEt");
		support.setBaseUrl("http://photos.example.net:81");
		when(request.getParameterNames()).thenReturn(Collections.enumeration(requestParameters.keySet()));
		for (String key : requestParameters.keySet()) {
			when(request.getParameterValues(key)).thenReturn(requestParameters.get(key));
		}

		baseString = support.getSignatureBaseString(request);
		assertEquals(
				"GET&http%3A%2F%2Fphotos.example.net%3A81%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal",
				baseString);
	}
}
