package org.springframework.security.oauth2.consumer;

import junit.framework.TestCase;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;

import java.io.IOException;

import static org.easymock.EasyMock.*;

/**
 * @author Max Gorbunov
 */
public class TestOAuth2ErrorHandler extends TestCase {
  private ClientHttpResponse response;
  private OAuth2ErrorHandler handler;

  @Override
  protected void setUp() throws Exception {
    response = createMock(ClientHttpResponse.class);
    handler = new OAuth2ErrorHandler();
  }

  public void testHandleExpiredTokenError() throws IOException {
    final HttpHeaders headers = new HttpHeaders();
    headers.add("WWW-Authenticate", OAuth2ErrorHandler.AUTH_HEADER + "error=invalid_token");
    response.getHeaders();
    expectLastCall().andReturn(headers);
    replay(response);

    try {
      handler.handleError(response);
    }
    catch (InvalidTokenException e) {
      verify(response);
      return;
    }

    fail("Expected exception was not thrown");
  }
}
