package org.springframework.security.oauth2.consumer;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expectLastCall;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.fail;

import java.io.IOException;

import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;

/**
 * @author Max Gorbunov
 */
public class TestOAuth2ErrorHandler {
	private ClientHttpResponse response;
	private OAuth2ErrorHandler handler;

	@Before
	public void setUp() throws Exception {
		response = createMock(ClientHttpResponse.class);
		handler = new OAuth2ErrorHandler();
	}

	@Test
	public void testHandleExpiredTokenError() throws IOException {
		final HttpHeaders headers = new HttpHeaders();
		headers.add("WWW-Authenticate", OAuth2ErrorHandler.AUTH_HEADER + "error=invalid_token");
		response.getHeaders();
		expectLastCall().andReturn(headers);
		replay(response);

		try {
			handler.handleError(response);
		} catch (InvalidTokenException e) {
			verify(response);
			return;
		}

		fail("Expected exception was not thrown");
	}
}
