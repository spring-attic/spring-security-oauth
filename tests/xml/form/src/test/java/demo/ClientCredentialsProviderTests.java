package demo;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;

import org.junit.Test;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsAccessTokenProvider;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.ResponseErrorHandler;

import sparklr.common.AbstractClientCredentialsProviderTests;

/**
 * @author Dave Syer
 */
@SpringApplicationConfiguration(classes=Application.class)
public class ClientCredentialsProviderTests extends AbstractClientCredentialsProviderTests {

	private HttpHeaders responseHeaders;

	private HttpStatus responseStatus;

	/**
	 * tests the basic provider with form based client credentials
	 */
	@Test
	@OAuth2ContextConfiguration(FormClientCredentials.class)
	public void testPostForTokenWithForm() throws Exception {
		OAuth2AccessToken token = context.getAccessToken();
		assertNull(token.getRefreshToken());
	}

	@Test
	@OAuth2ContextConfiguration(resource = InvalidClientCredentials.class, initialize = false)
	public void testInvalidCredentialsWithFormAuthentication() throws Exception {
		context.setAccessTokenProvider(new ClientCredentialsAccessTokenProvider() {
			@Override
			protected ResponseErrorHandler getResponseErrorHandler() {
				return new DefaultResponseErrorHandler() {
					public void handleError(ClientHttpResponse response) throws IOException {
						responseHeaders = response.getHeaders();
						responseStatus = response.getStatusCode();
					}
				};
			}
		});
		try {
			context.getAccessToken();
			fail("Expected ResourceAccessException");
		}
		catch (Exception e) {
			// ignore
		}
		// System.err.println(responseHeaders);
		String header = responseHeaders.getFirst("WWW-Authenticate");
		assertTrue("Wrong header: " + header, header.contains("Form realm"));
		assertEquals(HttpStatus.UNAUTHORIZED, responseStatus);
	}

	static class FormClientCredentials extends ClientCredentials {
		public FormClientCredentials(Object target) {
			super(target);
			setClientAuthenticationScheme(AuthenticationScheme.form);
		}
	}

	static class InvalidClientCredentials extends ClientCredentials {
		public InvalidClientCredentials(Object target) {
			super(target);
			setClientId("my-client-with-secret");
			setClientSecret("wrong");
			setClientAuthenticationScheme(AuthenticationScheme.form);
		}
	}

}
