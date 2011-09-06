package org.springframework.security.oauth2.consumer;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expectLastCall;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.consumer.http.OAuth2ErrorHandler;
import org.springframework.web.client.HttpClientErrorException;

/**
 * @author Max Gorbunov
 * @author Dave Syer
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
		headers.add("WWW-Authenticate", OAuth2AccessToken.BEARER_TYPE + " error=invalid_token");
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

	@Test
	public void testHandleErrorWithMissingHeader() throws IOException {

		final HttpHeaders headers = new HttpHeaders();
		response.getHeaders();
		expectLastCall().andReturn(headers).anyTimes();
		response.getStatusCode();
		expectLastCall().andReturn(HttpStatus.BAD_REQUEST);
		response.getBody();
		expectLastCall().andReturn(new ByteArrayInputStream(new byte[0]));
		response.getStatusText();
		expectLastCall().andReturn(HttpStatus.BAD_REQUEST.toString());
		replay(response);

		try {
			handler.handleError(response);
		} catch (HttpClientErrorException e) {
			verify(response);
			return;
		}

		fail("Expected exception was not thrown");
	}
}
