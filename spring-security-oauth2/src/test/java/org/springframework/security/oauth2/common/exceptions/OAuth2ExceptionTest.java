package org.springframework.security.oauth2.common.exceptions;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.HashMap;

public class OAuth2ExceptionTest {

  @Rule public ExpectedException thrown = ExpectedException.none();

  @Test
  public void testCreate1() {
    OAuth2Exception oAuth2Exception = OAuth2Exception.create("a'b'c", ",");

    Assert.assertNull(oAuth2Exception.getAdditionalInformation());
    Assert.assertEquals(",", oAuth2Exception.getMessage());
  }

  @Test
  public void testCreate2() {
    OAuth2Exception oAuth2Exception = OAuth2Exception.create("invalid_grant", null);

    Assert.assertNull(oAuth2Exception.getAdditionalInformation());
    Assert.assertEquals(oAuth2Exception.getClass(), InvalidGrantException.class);
    Assert.assertEquals("invalid_grant", oAuth2Exception.getMessage());
  }

  @Test
  public void testCreate3() {
    OAuth2Exception oAuth2Exception = OAuth2Exception.create("unsupported_grant_type", null);

    Assert.assertNull(oAuth2Exception.getAdditionalInformation());
    Assert.assertEquals(oAuth2Exception.getClass(), UnsupportedGrantTypeException.class);
    Assert.assertEquals("unsupported_grant_type", oAuth2Exception.getMessage());
  }

  @Test
  public void testCreate4() {
    OAuth2Exception oAuth2Exception = OAuth2Exception.create("invalid_token", null);

    Assert.assertNull(oAuth2Exception.getAdditionalInformation());
    Assert.assertEquals(oAuth2Exception.getClass(), InvalidTokenException.class);
    Assert.assertEquals("invalid_token", oAuth2Exception.getMessage());
  }

  @Test
  public void testCreate5() {
    OAuth2Exception oAuth2Exception = OAuth2Exception.create("invalid_client", null);

    Assert.assertNull(oAuth2Exception.getAdditionalInformation());
    Assert.assertEquals(oAuth2Exception.getClass(), InvalidClientException.class);
    Assert.assertEquals("invalid_client", oAuth2Exception.getMessage());
  }

  @Test
  public void testCreate6() {
    OAuth2Exception oAuth2Exception = OAuth2Exception.create("access_denied", null);

    Assert.assertNull(oAuth2Exception.getAdditionalInformation());
    Assert.assertEquals(oAuth2Exception.getClass(), UserDeniedAuthorizationException.class);
    Assert.assertEquals("access_denied", oAuth2Exception.getMessage());
  }

  @Test
  public void testCreate7() {
    OAuth2Exception oAuth2Exception = OAuth2Exception.create("invalid_scope", null);

    Assert.assertNull(oAuth2Exception.getAdditionalInformation());
    Assert.assertEquals(oAuth2Exception.getClass(), InvalidScopeException.class);
    Assert.assertEquals("invalid_scope", oAuth2Exception.getMessage());
  }

  @Test
  public void testCreate8() {
    OAuth2Exception oAuth2Exception = OAuth2Exception.create("invalid_request", null);

    Assert.assertNull(oAuth2Exception.getAdditionalInformation());
    Assert.assertEquals(oAuth2Exception.getClass(), InvalidRequestException.class);
    Assert.assertEquals("invalid_request", oAuth2Exception.getMessage());
  }

  @Test
  public void testCreate9() {
    OAuth2Exception oAuth2Exception = OAuth2Exception.create("unauthorized_client", null);

    Assert.assertNull(oAuth2Exception.getAdditionalInformation());
    Assert.assertEquals(oAuth2Exception.getClass(), UnauthorizedClientException.class);
    Assert.assertEquals("unauthorized_client", oAuth2Exception.getMessage());
  }

  @Test
  public void testCreate10() {
    OAuth2Exception oAuth2Exception = OAuth2Exception.create("unsupported_response_type", null);

    Assert.assertNull(oAuth2Exception.getAdditionalInformation());
    Assert.assertEquals(oAuth2Exception.getClass(), UnsupportedResponseTypeException.class);
    Assert.assertEquals("unsupported_response_type", oAuth2Exception.getMessage());
  }

  @Test
  public void testCreate11() {
    OAuth2Exception oAuth2Exception = OAuth2Exception.create("redirect_uri_mismatch", null);

    Assert.assertNull(oAuth2Exception.getAdditionalInformation());
    Assert.assertEquals(oAuth2Exception.getClass(), RedirectMismatchException.class);
    Assert.assertEquals("redirect_uri_mismatch", oAuth2Exception.getMessage());
  }
  
  @Test
  public void testGetHttpErrorCode() {
    Assert.assertEquals(400, new OAuth2Exception("3").getHttpErrorCode());
  }

  @Test
  public void testGetOAuth2ErrorCode() {
    Assert.assertEquals("invalid_request", new OAuth2Exception("3").getOAuth2ErrorCode());
  }

  @Test
  public void testToString() {
    Assert.assertEquals("error=\"invalid_request\", error_description=\"3\"", new OAuth2Exception("3").toString());
  }

  @Test
  public void testValueOf() {
    OAuth2Exception oAuth2Exception = OAuth2Exception.valueOf(new HashMap<String, String>());

    Assert.assertNull(oAuth2Exception.getAdditionalInformation());
    Assert.assertEquals("OAuth Error", oAuth2Exception.getMessage());

    HashMap<String, String> errorParams = new HashMap<String, String>();
    errorParams.put(null, null);

    thrown.expect(NullPointerException.class);
    OAuth2Exception.valueOf(errorParams);
  }
}
