/**
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
 **/

package net.oauth.signature;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;

import net.oauth.OAuthMessage;
import net.oauth.server.OAuthServlet;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.oauth.common.OAuthCodec;
import org.springframework.security.oauth.common.signature.HMAC_SHA1SignatureMethod;
import org.springframework.security.oauth.provider.filter.CoreOAuthProviderSupport;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
@RunWith(MockitoJUnitRunner.class)
public class GoogleCodeCompatibilityTests {
	@Mock
	private HttpServletRequest request;

	/**
	 * tests compatibilty with the google code HMAC_SHA1 signature.
	 */
	@Test
	public void testHMAC_SHA1_1() throws Exception {
		HMAC_SHA1 theirMethod = new HMAC_SHA1();
		String baseString = "GET&http%3A%2F%2Flocalhost%3A8080%2Fgrailscrowd%2Foauth%2Frequest_token&oauth_consumer_key%3Dtonrconsumerkey%26oauth_nonce%3D1227967049787975000%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1227967049%26oauth_version%3D1.0";
		theirMethod.setConsumerSecret("xxxxxx");
		theirMethod.setTokenSecret("");
		SecretKeySpec spec = new SecretKeySpec("xxxxxx&".getBytes("UTF-8"), HMAC_SHA1SignatureMethod.MAC_NAME);
		HMAC_SHA1SignatureMethod ourMethod = new HMAC_SHA1SignatureMethod(spec);
		String theirSignature = theirMethod.getSignature(baseString);
		String ourSignature = ourMethod.sign(baseString);
		assertEquals(theirSignature, ourSignature);
	}

	/**
	 * tests compatibility of calculating the signature base string.
	 */
	@Test
	public void testCalculateSignatureBaseString() throws Exception {
		final String baseUrl = "http://www.springframework.org/schema/security/";
		CoreOAuthProviderSupport support = new CoreOAuthProviderSupport() {
			@Override
			protected String getBaseUrl(HttpServletRequest request) {
				return baseUrl;
			}
		};

		Map<String, String[]> parameterMap = new HashMap<String, String[]>();
		parameterMap.put("a", new String[] { "value-a" });
		parameterMap.put("b", new String[] { "value-b" });
		parameterMap.put("c", new String[] { "value-c" });
		parameterMap.put("param[1]", new String[] { "aaa", "bbb" });

		when(request.getParameterNames()).thenReturn(Collections.enumeration(parameterMap.keySet()));
		for (Map.Entry<String, String[]> param : parameterMap.entrySet()) {
			when(request.getParameterValues(param.getKey())).thenReturn(param.getValue());
		}

		String header = "OAuth realm=\"http://sp.example.com/\","
				+ "                oauth_consumer_key=\"0685bd9184jfhq22\","
				+ "                oauth_token=\"ad180jjd733klru7\","
				+ "                oauth_signature_method=\"HMAC-SHA1\","
				+ "                oauth_signature=\"wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D\","
				+ "                oauth_timestamp=\"137131200\"," + "                oauth_callback=\""
				+ OAuthCodec.oauthEncode("http://myhost.com/callback") + "\","
				+ "                oauth_nonce=\"4572616e48616d6d65724c61686176\","
				+ "                oauth_version=\"1.0\"";
		when(request.getHeaders("Authorization")).thenReturn(Collections.enumeration(Arrays.asList(header)));
		when(request.getMethod()).thenReturn("GET");
		String ours = support.getSignatureBaseString(request);

		when(request.getHeaders("Authorization")).thenReturn(Collections.enumeration(Arrays.asList(header)));
		when(request.getParameterMap()).thenReturn(parameterMap);
		when(request.getHeaderNames()).thenReturn(null);
		OAuthMessage message = OAuthServlet.getMessage(request, baseUrl);

		String theirs = OAuthSignatureMethod.getBaseString(message);
		assertEquals(theirs, ours);
	}

}
