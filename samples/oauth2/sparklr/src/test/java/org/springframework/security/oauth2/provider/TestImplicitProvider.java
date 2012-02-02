package org.springframework.security.oauth2.provider;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.net.URI;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.provider.ServerRunning.UriBuilder;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class TestImplicitProvider {

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();

	private String implicitUrl() {
		URI uri = serverRunning.buildUri("/sparklr2/oauth/authorize").queryParam("response_type", "token")
				.queryParam("state", "mystateid").queryParam("client_id", "my-less-trusted-client")
				.queryParam("redirect_uri", "http://anywhere").queryParam("scope", "read").build();
		return uri.toString();
	}

	private String buildUrl(String location, Map<String,String> parameters) {
		UriBuilder uriBuilder = serverRunning.buildUri(location);
		for(Entry<String, String> entry: parameters.entrySet()){
			uriBuilder.queryParam(entry.getKey(), entry.getValue());
		}
		return uriBuilder.build().toString();
	}

	/**
	 * tests the basic implicit provider
	 */
	@Test
	public void testBasicImplicitProvider() throws Exception {

		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.TEXT_HTML));

		ResponseEntity<Void> result = serverRunning.getForResponse(implicitUrl(), headers);
		assertEquals(HttpStatus.FOUND, result.getStatusCode());
		String location = result.getHeaders().getLocation().toString();
		String cookie = result.getHeaders().getFirst("Set-Cookie");

		assertNotNull("Expected cookie in " + result.getHeaders(), cookie);
		headers.set("Cookie", cookie);

		ResponseEntity<String> response = serverRunning.getForString(location, headers);
		// should be directed to the login screen...
		assertTrue(response.getBody().contains("/login.do"));
		assertTrue(response.getBody().contains("username"));
		assertTrue(response.getBody().contains("password"));

		location = "/sparklr2/login.do";

		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("j_username", "marissa");
		formData.add("j_password", "koala");

		result = serverRunning.postForRedirect(location, headers, formData);

		System.err.println(result.getStatusCode());
		System.err.println(result.getHeaders());

		assertNotNull(result.getHeaders().getLocation());
		assertTrue(result.getHeaders().getLocation().toString().matches("http://anywhere#access_token=.+"));
	}
	
	/**
	 * tests the basic implicit provider
	 */
	@Test
	public void testGetForToken() throws Exception {

		HttpHeaders headers = new HttpHeaders();
		ResponseEntity<Void> result;

		MultiValueMap<String, String> formData;
		formData = new LinkedMultiValueMap<String, String>();
		formData.add("j_username", "marissa");
		formData.add("j_password", "koala");

		String location = "/sparklr2/login.do";
		result = serverRunning.postForStatus(location, headers, formData);
		assertEquals(HttpStatus.FOUND, result.getStatusCode());
		String cookie = result.getHeaders().getFirst("Set-Cookie");

		assertNotNull("Expected cookie in " + result.getHeaders(), cookie);
		headers.set("Cookie", cookie);

		location = "/sparklr2/oauth/authorize";
		Map<String, String> data = new HashMap<String, String>();
		data.put("response_type", "token");
		data.put("state", "mystateid");
		data.put("client_id", "my-less-trusted-client");
		data.put("redirect_uri", "http://anywhere");
		data.put("scope", "read");
		
		result = serverRunning.getForResponse(buildUrl(location, data), headers);
		assertEquals(HttpStatus.FOUND, result.getStatusCode());

		location = result.getHeaders().getLocation().toString();
		System.err.println(location);
		URI redirection = serverRunning.buildUri(location).build();
		assertEquals("anywhere", redirection.getHost());
		assertEquals("http", redirection.getScheme());

		// we've got the access token.
		String fragment = redirection.getFragment();
		assertNotNull("No fragment in redirect: "+redirection, fragment);
		
	}

}
