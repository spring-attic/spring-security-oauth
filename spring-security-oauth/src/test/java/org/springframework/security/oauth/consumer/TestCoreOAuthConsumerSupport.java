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

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.reset;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import javax.servlet.http.HttpServletRequest;

import org.junit.Test;
import org.springframework.security.oauth.common.OAuthConsumerParameter;
import org.springframework.security.oauth.common.signature.HMAC_SHA1SignatureMethod;
import org.springframework.security.oauth.common.signature.OAuthSignatureMethod;
import org.springframework.security.oauth.common.signature.OAuthSignatureMethodFactory;
import org.springframework.security.oauth.common.signature.SharedConsumerSecret;
import org.springframework.security.oauth.consumer.net.DefaultOAuthURLStreamHandlerFactory;
import org.springframework.security.oauth.consumer.token.OAuthConsumerToken;

/**
 * @author Ryan Heaton
 */
public class TestCoreOAuthConsumerSupport {

	/**
	 * afterPropertiesSet
	 */
	@Test
	public void testAfterPropertiesSet() throws Exception {
		try {
			new CoreOAuthConsumerSupport().afterPropertiesSet();
			fail("should required a protected resource details service.");
		} catch (IllegalArgumentException e) {
		}
	}

	/**
	 * readResouce
	 */
	@Test
	public void testReadResouce() throws Exception {
		ProtectedResourceDetails details = createMock(ProtectedResourceDetails.class);
		OAuthConsumerToken token = new OAuthConsumerToken();
		URL url = new URL("http://myhost.com/resource?with=some&query=params&too");
		final ConnectionProps connectionProps = new ConnectionProps();
		final ByteArrayInputStream inputStream = new ByteArrayInputStream(new byte[0]);
		final HttpURLConnectionForTestingPurposes connectionMock = new HttpURLConnectionForTestingPurposes(url) {
			@Override
			public void setRequestMethod(String method) throws ProtocolException {
				connectionProps.method = method;
			}

			@Override
			public void setDoOutput(boolean dooutput) {
				connectionProps.doOutput = dooutput;
			}

			@Override
			public void connect() throws IOException {
				connectionProps.connected = true;
			}

			@Override
			public OutputStream getOutputStream() throws IOException {
				ByteArrayOutputStream out = new ByteArrayOutputStream();
				connectionProps.outputStream = out;
				return out;
			}

			@Override
			public int getResponseCode() throws IOException {
				return connectionProps.responseCode;
			}

			@Override
			public String getResponseMessage() throws IOException {
				return connectionProps.responseMessage;
			}

			@Override
			public InputStream getInputStream() throws IOException {
				return inputStream;
			}

			@Override
			public String getHeaderField(String name) {
				return connectionProps.headerFields.get(name);
			}
		};

		CoreOAuthConsumerSupport support = new CoreOAuthConsumerSupport() {
			@Override
			public URL configureURLForProtectedAccess(URL url, OAuthConsumerToken accessToken,
					ProtectedResourceDetails details, String httpMethod, Map<String, String> additionalParameters)
					throws OAuthRequestFailedException {
				try {
					return new URL(url.getProtocol(), url.getHost(), url.getPort(), url.getFile(),
							new SteamHandlerForTestingPurposes(connectionMock));
				} catch (MalformedURLException e) {
					throw new RuntimeException(e);
				}
			}

			@Override
			public String getOAuthQueryString(ProtectedResourceDetails details, OAuthConsumerToken accessToken,
					URL url, String httpMethod, Map<String, String> additionalParameters) {
				return "POSTBODY";
			}
		};
		support.setStreamHandlerFactory(new DefaultOAuthURLStreamHandlerFactory());

		expect(details.getAuthorizationHeaderRealm()).andReturn("realm1");
		expect(details.isAcceptsAuthorizationHeader()).andReturn(true);
		expect(details.getAdditionalRequestHeaders()).andReturn(null);
		replay(details);
		try {
			support.readResource(details, url, "POST", token, null, null);
			fail("shouldn't have been a valid response code.");
		} catch (OAuthRequestFailedException e) {
			// fall through...
		}
		verify(details);
		reset(details);
		assertFalse(connectionProps.doOutput);
		assertEquals("POST", connectionProps.method);
		assertTrue(connectionProps.connected);
		connectionProps.reset();

		expect(details.getAuthorizationHeaderRealm()).andReturn(null);
		expect(details.isAcceptsAuthorizationHeader()).andReturn(true);
		expect(details.getAdditionalRequestHeaders()).andReturn(null);
		connectionProps.responseCode = 400;
		connectionProps.responseMessage = "Nasty";
		replay(details);
		try {
			support.readResource(details, url, "POST", token, null, null);
			fail("shouldn't have been a valid response code.");
		} catch (OAuthRequestFailedException e) {
			// fall through...
		}
		verify(details);
		reset(details);
		assertFalse(connectionProps.doOutput);
		assertEquals("POST", connectionProps.method);
		assertTrue(connectionProps.connected);
		connectionProps.reset();

		expect(details.getAuthorizationHeaderRealm()).andReturn(null);
		expect(details.isAcceptsAuthorizationHeader()).andReturn(true);
		expect(details.getAdditionalRequestHeaders()).andReturn(null);
		connectionProps.responseCode = 401;
		connectionProps.responseMessage = "Bad Realm";
		connectionProps.headerFields.put("WWW-Authenticate", "realm=\"goodrealm\"");
		replay(details);
		try {
			support.readResource(details, url, "POST", token, null, null);
			fail("shouldn't have been a valid response code.");
		} catch (InvalidOAuthRealmException e) {
			// fall through...
		}
		verify(details);
		reset(details);
		assertFalse(connectionProps.doOutput);
		assertEquals("POST", connectionProps.method);
		assertTrue(connectionProps.connected);
		connectionProps.reset();

		expect(details.getAuthorizationHeaderRealm()).andReturn(null);
		expect(details.isAcceptsAuthorizationHeader()).andReturn(true);
		expect(details.getAdditionalRequestHeaders()).andReturn(null);
		connectionProps.responseCode = 200;
		connectionProps.responseMessage = "Congrats";
		replay(details);
		assertSame(inputStream, support.readResource(details, url, "GET", token, null, null));
		verify(details);
		reset(details);
		assertFalse(connectionProps.doOutput);
		assertEquals("GET", connectionProps.method);
		assertTrue(connectionProps.connected);
		connectionProps.reset();

		expect(details.getAuthorizationHeaderRealm()).andReturn(null);
		expect(details.isAcceptsAuthorizationHeader()).andReturn(false);
		expect(details.getAdditionalRequestHeaders()).andReturn(null);
		connectionProps.responseCode = 200;
		connectionProps.responseMessage = "Congrats";
		replay(details);
		assertSame(inputStream, support.readResource(details, url, "POST", token, null, null));
		assertEquals("POSTBODY", new String(((ByteArrayOutputStream) connectionProps.outputStream).toByteArray()));
		verify(details);
		reset(details);
		assertTrue(connectionProps.doOutput);
		assertEquals("POST", connectionProps.method);
		assertTrue(connectionProps.connected);
		connectionProps.reset();
	}

	/**
	 * configureURLForProtectedAccess
	 */
	@Test
	public void testConfigureURLForProtectedAccess() throws Exception {
		CoreOAuthConsumerSupport support = new CoreOAuthConsumerSupport() {
			// Inherited.
			@Override
			public String getOAuthQueryString(ProtectedResourceDetails details, OAuthConsumerToken accessToken,
					URL url, String httpMethod, Map<String, String> additionalParameters) {
				return "myquerystring";
			}
		};
		support.setStreamHandlerFactory(new DefaultOAuthURLStreamHandlerFactory());
		ProtectedResourceDetails details = createMock(ProtectedResourceDetails.class);
		OAuthConsumerToken token = new OAuthConsumerToken();
		URL url = new URL("https://myhost.com/somepath?with=some&query=params&too");

		expect(details.isAcceptsAuthorizationHeader()).andReturn(true);
		replay(details);
		assertEquals("https://myhost.com/somepath?with=some&query=params&too",
				support.configureURLForProtectedAccess(url, token, details, "GET", null).toString());
		verify(details);
		reset(details);

		expect(details.isAcceptsAuthorizationHeader()).andReturn(false);
		replay(details);
		assertEquals("https://myhost.com/somepath?myquerystring",
				support.configureURLForProtectedAccess(url, token, details, "GET", null).toString());
		verify(details);
		reset(details);

		replay(details);
		assertEquals("https://myhost.com/somepath?with=some&query=params&too",
				support.configureURLForProtectedAccess(url, token, details, "POST", null).toString());
		verify(details);
		reset(details);

		replay(details);
		assertEquals("https://myhost.com/somepath?with=some&query=params&too",
				support.configureURLForProtectedAccess(url, token, details, "PUT", null).toString());
		verify(details);
		reset(details);
	}

	/**
	 * test getAuthorizationHeader
	 */
	@Test
	public void testGetAuthorizationHeader() throws Exception {
		final TreeMap<String, Set<CharSequence>> params = new TreeMap<String, Set<CharSequence>>();
		CoreOAuthConsumerSupport support = new CoreOAuthConsumerSupport() {
			@Override
			protected Map<String, Set<CharSequence>> loadOAuthParameters(ProtectedResourceDetails details,
					URL requestURL, OAuthConsumerToken requestToken, String httpMethod,
					Map<String, String> additionalParameters) {
				return params;
			}
		};
		URL url = new URL("https://myhost.com/somepath?with=some&query=params&too");
		OAuthConsumerToken token = new OAuthConsumerToken();
		ProtectedResourceDetails details = createMock(ProtectedResourceDetails.class);

		expect(details.isAcceptsAuthorizationHeader()).andReturn(false);
		replay(details);
		assertNull(support.getAuthorizationHeader(details, token, url, "POST", null));
		verify(details);
		reset(details);

		params.put("with", Collections.singleton((CharSequence) "some"));
		params.put("query", Collections.singleton((CharSequence) "params"));
		params.put("too", null);
		expect(details.isAcceptsAuthorizationHeader()).andReturn(true);
		expect(details.getAuthorizationHeaderRealm()).andReturn("myrealm");
		replay(details);
		assertEquals("OAuth realm=\"myrealm\", query=\"params\", with=\"some\"",
				support.getAuthorizationHeader(details, token, url, "POST", null));
		verify(details);
		reset(details);

		params.put(OAuthConsumerParameter.oauth_consumer_key.toString(), Collections.singleton((CharSequence) "mykey"));
		params.put(OAuthConsumerParameter.oauth_nonce.toString(), Collections.singleton((CharSequence) "mynonce"));
		params.put(OAuthConsumerParameter.oauth_timestamp.toString(), Collections.singleton((CharSequence) "myts"));
		expect(details.isAcceptsAuthorizationHeader()).andReturn(true);
		expect(details.getAuthorizationHeaderRealm()).andReturn("myrealm");
		replay(details);
		assertEquals(
				"OAuth realm=\"myrealm\", oauth_consumer_key=\"mykey\", oauth_nonce=\"mynonce\", oauth_timestamp=\"myts\", query=\"params\", with=\"some\"",
				support.getAuthorizationHeader(details, token, url, "POST", null));
		verify(details);
		reset(details);
	}

	/**
	 * getOAuthQueryString
	 */
	@Test
	public void testGetOAuthQueryString() throws Exception {
		final TreeMap<String, Set<CharSequence>> params = new TreeMap<String, Set<CharSequence>>();
		CoreOAuthConsumerSupport support = new CoreOAuthConsumerSupport() {
			@Override
			protected Map<String, Set<CharSequence>> loadOAuthParameters(ProtectedResourceDetails details,
					URL requestURL, OAuthConsumerToken requestToken, String httpMethod,
					Map<String, String> additionalParameters) {
				return params;
			}
		};

		URL url = new URL("https://myhost.com/somepath?with=some&query=params&too");
		OAuthConsumerToken token = new OAuthConsumerToken();
		ProtectedResourceDetails details = createMock(ProtectedResourceDetails.class);

		expect(details.isAcceptsAuthorizationHeader()).andReturn(true);
		params.put("with", Collections.singleton((CharSequence) "some"));
		params.put("query", Collections.singleton((CharSequence) "params"));
		params.put("too", null);
		params.put(OAuthConsumerParameter.oauth_consumer_key.toString(), Collections.singleton((CharSequence) "mykey"));
		params.put(OAuthConsumerParameter.oauth_nonce.toString(), Collections.singleton((CharSequence) "mynonce"));
		params.put(OAuthConsumerParameter.oauth_timestamp.toString(), Collections.singleton((CharSequence) "myts"));
		replay(details);
		assertEquals("query=params&too&with=some", support.getOAuthQueryString(details, token, url, "POST", null));
		verify(details);
		reset(details);

		expect(details.isAcceptsAuthorizationHeader()).andReturn(false);
		params.put("with", Collections.singleton((CharSequence) "some"));
		params.put("query", Collections.singleton((CharSequence) "params"));
		params.put("too", null);
		params.put(OAuthConsumerParameter.oauth_consumer_key.toString(), Collections.singleton((CharSequence) "mykey"));
		params.put(OAuthConsumerParameter.oauth_nonce.toString(), Collections.singleton((CharSequence) "mynonce"));
		params.put(OAuthConsumerParameter.oauth_timestamp.toString(), Collections.singleton((CharSequence) "myts"));
		replay(details);
		assertEquals("oauth_consumer_key=mykey&oauth_nonce=mynonce&oauth_timestamp=myts&query=params&too&with=some",
				support.getOAuthQueryString(details, token, url, "POST", null));
		verify(details);
		reset(details);

		expect(details.isAcceptsAuthorizationHeader()).andReturn(false);
		params.put("with", Collections.singleton((CharSequence) "some"));
		String encoded_space = URLEncoder.encode(" ", "utf-8");
		params.put("query", Collections.singleton((CharSequence) ("params" + encoded_space + "spaced")));
		params.put("too", null);
		params.put(OAuthConsumerParameter.oauth_consumer_key.toString(), Collections.singleton((CharSequence) "mykey"));
		params.put(OAuthConsumerParameter.oauth_nonce.toString(), Collections.singleton((CharSequence) "mynonce"));
		params.put(OAuthConsumerParameter.oauth_timestamp.toString(), Collections.singleton((CharSequence) "myts"));
		replay(details);
		assertEquals("oauth_consumer_key=mykey&oauth_nonce=mynonce&oauth_timestamp=myts&query=params" + encoded_space
				+ "spaced&too&with=some", support.getOAuthQueryString(details, token, url, "POST", null));
		verify(details);
		reset(details);
	}

	/**
	 * getTokenFromProvider
	 */
	@Test
	public void testGetTokenFromProvider() throws Exception {
		final ByteArrayInputStream in = new ByteArrayInputStream(
				"oauth_token=mytoken&oauth_token_secret=mytokensecret".getBytes("UTF-8"));
		CoreOAuthConsumerSupport support = new CoreOAuthConsumerSupport() {
			@Override
			protected InputStream readResource(ProtectedResourceDetails details, URL url, String httpMethod,
					OAuthConsumerToken token, Map<String, String> additionalParameters,
					Map<String, String> additionalRequestHeaders) {
				return in;
			}
		};

		ProtectedResourceDetails details = createMock(ProtectedResourceDetails.class);
		URL url = new URL("https://myhost.com/somepath?with=some&query=params&too");

		expect(details.getId()).andReturn("resourceId");
		replay(details);
		OAuthConsumerToken token = support.getTokenFromProvider(details, url, "POST", null, null);
		verify(details);
		reset(details);
		assertFalse(token.isAccessToken());
		assertEquals("mytoken", token.getValue());
		assertEquals("mytokensecret", token.getSecret());
		assertEquals("resourceId", token.getResourceId());

	}

	/**
	 * loadOAuthParameters
	 */
	@Test
	public void testLoadOAuthParameters() throws Exception {
		ProtectedResourceDetails details = createMock(ProtectedResourceDetails.class);
		URL url = new URL("https://myhost.com/somepath?with=some&query=params&too");
		CoreOAuthConsumerSupport support = new CoreOAuthConsumerSupport() {
			@Override
			protected String getSignatureBaseString(Map<String, Set<CharSequence>> oauthParams, URL requestURL,
					String httpMethod) {
				return "MYSIGBASESTRING";
			}
		};
		OAuthSignatureMethodFactory sigFactory = createMock(OAuthSignatureMethodFactory.class);
		support.setSignatureFactory(sigFactory);
		OAuthConsumerToken token = new OAuthConsumerToken();
		OAuthSignatureMethod sigMethod = createMock(OAuthSignatureMethod.class);

		expect(details.getConsumerKey()).andReturn("my-consumer-key");
		expect(details.getSignatureMethod()).andReturn(HMAC_SHA1SignatureMethod.SIGNATURE_NAME);
		expect(details.getSignatureMethod()).andReturn(HMAC_SHA1SignatureMethod.SIGNATURE_NAME);
		SharedConsumerSecret secret = new SharedConsumerSecret("shh!!!");
		expect(details.getSharedSecret()).andReturn(secret);
		expect(sigFactory.getSignatureMethod(HMAC_SHA1SignatureMethod.SIGNATURE_NAME, secret, null)).andReturn(
				sigMethod);
		expect(sigMethod.sign("MYSIGBASESTRING")).andReturn("MYSIGNATURE");

		replay(details, sigFactory, sigMethod);
		Map<String, Set<CharSequence>> params = support.loadOAuthParameters(details, url, token, "POST", null);
		verify(details, sigFactory, sigMethod);
		reset(details, sigFactory, sigMethod);
		assertEquals("some", params.remove("with").iterator().next().toString());
		assertEquals("params", params.remove("query").iterator().next().toString());
		assertTrue(params.containsKey("too"));
		assertTrue(params.remove("too").isEmpty());
		assertNull(params.remove(OAuthConsumerParameter.oauth_token.toString()));
		assertNotNull(params.remove(OAuthConsumerParameter.oauth_nonce.toString()).iterator().next());
		assertEquals("my-consumer-key", params.remove(OAuthConsumerParameter.oauth_consumer_key.toString()).iterator()
				.next());
		assertEquals("MYSIGNATURE", params.remove(OAuthConsumerParameter.oauth_signature.toString()).iterator().next());
		assertEquals("1.0", params.remove(OAuthConsumerParameter.oauth_version.toString()).iterator().next());
		assertEquals(HMAC_SHA1SignatureMethod.SIGNATURE_NAME,
				params.remove(OAuthConsumerParameter.oauth_signature_method.toString()).iterator().next());
		assertTrue(Long.parseLong(params.remove(OAuthConsumerParameter.oauth_timestamp.toString()).iterator().next()
				.toString()) <= (System.currentTimeMillis() / 1000));
		assertTrue(params.isEmpty());
	}

	/**
	 * tests getting the signature base string.
	 */
	@Test
	public void testGetSignatureBaseString() throws Exception {
		HttpServletRequest request = createMock(HttpServletRequest.class);
		Map<String, Set<CharSequence>> oauthParams = new HashMap<String, Set<CharSequence>>();
		oauthParams.put("oauth_consumer_key", Collections.singleton((CharSequence) "dpf43f3p2l4k3l03"));
		oauthParams.put("oauth_token", Collections.singleton((CharSequence) "nnch734d00sl2jdk"));
		oauthParams.put("oauth_signature_method", Collections.singleton((CharSequence) "HMAC-SHA1"));
		oauthParams.put("oauth_timestamp", Collections.singleton((CharSequence) "1191242096"));
		oauthParams.put("oauth_nonce", Collections.singleton((CharSequence) "kllo9940pd9333jh"));
		oauthParams.put("oauth_version", Collections.singleton((CharSequence) "1.0"));
		oauthParams.put("file", Collections.singleton((CharSequence) "vacation.jpg"));
		oauthParams.put("size", Collections.singleton((CharSequence) "original"));

		CoreOAuthConsumerSupport support = new CoreOAuthConsumerSupport();

		replay(request);
		String baseString = support.getSignatureBaseString(oauthParams, new URL("http://photos.example.net/photos"),
				"geT");
		verify(request);
		assertEquals(
				"GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal",
				baseString);
		reset(request);
	}
}
