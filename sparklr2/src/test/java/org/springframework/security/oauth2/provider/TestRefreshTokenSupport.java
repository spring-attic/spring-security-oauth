package org.springframework.security.oauth2.provider;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.core.util.MultivaluedMapImpl;
import junit.framework.TestCase;
import org.springframework.security.oauth2.common.DefaultOAuth2SerializationService;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;

/**
 * @author Ryan Heaton
 */
public class TestRefreshTokenSupport extends TestCase {

  /**
   * tests a happy-day flow of the native application profile.
   */
  public void testHappyDay() throws Exception {
    int port = 8080;
    Client client = Client.create();
    client.setFollowRedirects(false);

    MultivaluedMap<String, String> formData = new MultivaluedMapImpl();
    formData.add("grant_type", "password");
    formData.add("client_id", "my-trusted-client");
    formData.add("username", "marissa");
    formData.add("password", "koala");
    ClientResponse response = client.resource("http://localhost:" + port + "/sparklr/oauth/authorize")
      .type(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
      .post(ClientResponse.class, formData);
    assertEquals(200, response.getClientResponseStatus().getStatusCode());
    assertEquals("no-store", response.getHeaders().getFirst("Cache-Control"));

    DefaultOAuth2SerializationService serializationService = new DefaultOAuth2SerializationService();
    OAuth2AccessToken accessToken = serializationService.deserializeJsonAccessToken(response.getEntityInputStream());

    //now try and use the token to access a protected resource.

    //first make sure the resource is actually protected.
    response = client.resource("http://localhost:" + port + "/sparklr/json/photos").get(ClientResponse.class);
    assertFalse(200 == response.getClientResponseStatus().getStatusCode());

    //now make sure an authorized request is valid.
    response = client.resource("http://localhost:" + port + "/sparklr/json/photos")
      .header("Authorization", String.format("OAuth2 %s", accessToken.getValue()))
      .get(ClientResponse.class);
    assertEquals(200, response.getClientResponseStatus().getStatusCode());

    //now use the refresh token to get a new access token.
    assertNotNull(accessToken.getRefreshToken());
    formData = new MultivaluedMapImpl();
    formData.add("grant_type", "refresh_token");
    formData.add("client_id", "my-trusted-client");
    formData.add("refresh_token", accessToken.getRefreshToken().getValue());
    response = client.resource("http://localhost:" + port + "/sparklr/oauth/authorize")
      .type(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
      .post(ClientResponse.class, formData);
    assertEquals(200, response.getClientResponseStatus().getStatusCode());
    assertEquals("no-store", response.getHeaders().getFirst("Cache-Control"));
    OAuth2AccessToken newAccessToken = serializationService.deserializeJsonAccessToken(response.getEntityInputStream());
    assertFalse(newAccessToken.getValue().equals(accessToken.getValue()));

    //make sure the new access token can be used.
    response = client.resource("http://localhost:" + port + "/sparklr/json/photos")
      .header("Authorization", String.format("OAuth2 %s", newAccessToken.getValue()))
      .get(ClientResponse.class);
    assertEquals(200, response.getClientResponseStatus().getStatusCode());

    //make sure the old access token isn't valid anymore.
    response = client.resource("http://localhost:" + port + "/sparklr/json/photos")
      .header("Authorization", String.format("OAuth2 %s", accessToken.getValue()))
      .get(ClientResponse.class);
    assertEquals(401, response.getClientResponseStatus().getStatusCode());
  }
}
