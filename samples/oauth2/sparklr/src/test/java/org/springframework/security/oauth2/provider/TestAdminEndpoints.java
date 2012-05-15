package org.springframework.security.oauth2.provider;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

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

/**
 * @author Dave Syer
 */
public class TestAdminEndpoints {

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

		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

		HttpEntity<?> request = new HttpEntity<Void>(headers);
		assertEquals(
				HttpStatus.NO_CONTENT,
				serverRunning
						.getRestTemplate()
						.exchange(serverRunning.getUrl("/sparklr2/oauth/users/{user}/tokens/{token}"),
								HttpMethod.DELETE, request, Void.class, "marissa", token.getValue()).getStatusCode());

		ResponseEntity<String> result = serverRunning.getForString("/sparklr2/oauth/users/marissa/tokens", headers);
		assertEquals(HttpStatus.UNAUTHORIZED, result.getStatusCode());
		assertTrue(result.getBody().contains("invalid_token"));

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
		assertEquals(HttpStatus.FORBIDDEN, serverRunning.getStatusCode("/sparklr2/oauth/users/foo/tokens"));
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
		assertEquals(HttpStatus.FORBIDDEN,
				serverRunning.getStatusCode("/sparklr2/oauth/clients/my-client-with-registered-redirect/tokens"));
	}

	static class ResourceOwnerReadOnly extends ResourceOwnerPasswordResourceDetails {
		public ResourceOwnerReadOnly(Object target) {
			setClientId("my-trusted-client");
			setId(getClientId());
			setScope(Arrays.asList("read"));
			setUsername("marissa");
			setPassword("koala");
			TestAdminEndpoints test = (TestAdminEndpoints) target;
			setAccessTokenUri(test.serverRunning.getUrl("/sparklr2/oauth/token"));
		}
	}

	static class ClientCredentialsReadOnly extends ClientCredentialsResourceDetails {
		public ClientCredentialsReadOnly(Object target) {
			setClientId("my-client-with-registered-redirect");
			setId(getClientId());
			setScope(Arrays.asList("read"));
			TestAdminEndpoints test = (TestAdminEndpoints) target;
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
