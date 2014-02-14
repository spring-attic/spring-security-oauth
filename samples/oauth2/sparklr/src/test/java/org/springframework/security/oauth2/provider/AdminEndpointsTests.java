package org.springframework.security.oauth2.provider;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.util.Arrays;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.test.OAuth2ContextSetup;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InsufficientScopeException;
import org.springframework.security.oauth2.common.exceptions.UserDeniedAuthorizationException;

/**
 * @author Dave Syer
 */
public class AdminEndpointsTests {

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();

	@Rule
	public OAuth2ContextSetup context = OAuth2ContextSetup.standard(serverRunning);

	@Test
	@OAuth2ContextConfiguration(ResourceOwnerReadOnly.class)
	public void testListTokensByUser() throws Exception {
		ResponseEntity<String> result = serverRunning.getForString("/sparklr2/oauth/users/marissa/tokens");
		assertEquals(HttpStatus.OK, result.getStatusCode());
		// System.err.println(result.getBody());
		assertTrue(result.getBody().contains(context.getAccessToken().getValue()));
	}

	@Test
	@OAuth2ContextConfiguration(ResourceOwnerWriteOnly.class)
	public void testRevokeTokenByUser() throws Exception {

		OAuth2AccessToken token = context.getAccessToken();
		String tokenValueBeforeDeletion = token.getValue();

		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

		HttpEntity<?> request = new HttpEntity<Void>(headers);
		assertEquals(
				HttpStatus.NO_CONTENT,
				serverRunning
						.getRestTemplate()
						.exchange(serverRunning.getUrl("/sparklr2/oauth/users/{user}/tokens/{token}"),
								HttpMethod.DELETE, request, Void.class, "marissa", token.getValue()).getStatusCode());
		try {
			// The request above will delete the oauth token so that the next request will initially fail. However,
			// the failure will be detected and a new access token will be obtained.  The new access token
			// only has "write" scope and the requested resource needs "read" scope.  So, an insufficient_scope
			// exception should be thrown.
			ResponseEntity<String> result = serverRunning.getForString("/sparklr2/oauth/users/marissa/tokens", headers);
			fail("Should have thrown an exception");
			assertNotNull(result);
		} catch (InsufficientScopeException ex) {
			assertEquals(HttpStatus.FORBIDDEN.value(), ex.getHttpErrorCode());
			assertEquals("insufficient_scope", ex.getOAuth2ErrorCode());
			String secondTokenWithWriteOnlyScope = context.getOAuth2ClientContext().getAccessToken().getValue();
			assertNotNull(secondTokenWithWriteOnlyScope);
			assertFalse(secondTokenWithWriteOnlyScope.equals(tokenValueBeforeDeletion));
		}
	}

	@Test
	@OAuth2ContextConfiguration(ClientCredentialsReadOnly.class)
	public void testClientListsTokensOfUser() throws Exception {
		ResponseEntity<String> result = serverRunning.getForString("/sparklr2/oauth/users/marissa/tokens");
		assertEquals(HttpStatus.OK, result.getStatusCode());
		assertTrue(result.getBody().startsWith("["));
		assertTrue(result.getBody().endsWith("]"));
		assertTrue(result.getBody().length() > 0);
	}

	@Test
	@OAuth2ContextConfiguration(ResourceOwnerReadOnly.class)
	public void testCannotListTokensOfAnotherUser() throws Exception {
		try {
			serverRunning.getStatusCode("/sparklr2/oauth/users/foo/tokens");
			fail("Should have thrown an exception");
		} catch (UserDeniedAuthorizationException ex) {
			// assertEquals(HttpStatus.FORBIDDEN.value(), ex.getHttpErrorCode());
			assertEquals("access_denied", ex.getOAuth2ErrorCode());
		}
	}

	@Test
	@OAuth2ContextConfiguration(ClientCredentialsReadOnly.class)
	public void testListTokensByClient() throws Exception {
		ResponseEntity<String> result = serverRunning
				.getForString("/sparklr2/oauth/clients/my-client-with-registered-redirect/tokens");
		assertEquals(HttpStatus.OK, result.getStatusCode());
		assertTrue(result.getBody().contains(context.getAccessToken().getValue()));
	}

	@Test
	@OAuth2ContextConfiguration(ResourceOwnerReadOnly.class)
	public void testUserCannotListTokensOfClient() throws Exception {
		try {
			serverRunning.getStatusCode("/sparklr2/oauth/clients/my-client-with-registered-redirect/tokens");
			fail("Should have thrown an exception");
		} catch (UserDeniedAuthorizationException ex) {
			// assertEquals(HttpStatus.FORBIDDEN.value(), ex.getHttpErrorCode());
			assertEquals("access_denied", ex.getOAuth2ErrorCode());
		}
	}

	static class ResourceOwnerReadOnly extends ResourceOwnerPasswordResourceDetails {
		public ResourceOwnerReadOnly(Object target) {
			setClientId("my-trusted-client");
			setId(getClientId());
			setScope(Arrays.asList("read"));
			setUsername("marissa");
			setPassword("koala");
			AdminEndpointsTests test = (AdminEndpointsTests) target;
			setAccessTokenUri(test.serverRunning.getUrl("/sparklr2/oauth/token"));
		}
	}

	static class ClientCredentialsReadOnly extends ClientCredentialsResourceDetails {
		public ClientCredentialsReadOnly(Object target) {
			setClientId("my-client-with-registered-redirect");
			setId(getClientId());
			setScope(Arrays.asList("read"));
			AdminEndpointsTests test = (AdminEndpointsTests) target;
			setAccessTokenUri(test.serverRunning.getUrl("/sparklr2/oauth/token"));
		}
	}

	static class ResourceOwnerWriteOnly extends ResourceOwnerReadOnly {
		public ResourceOwnerWriteOnly(Object target) {
			super(target);
			setScope(Arrays.asList("write"));
		}
	}
}
