package org.springframework.security.oauth2.provider;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.core.util.MultivaluedMapImpl;
import junit.framework.TestCase;
import org.springframework.security.oauth2.common.DefaultOAuth2SerializationService;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2Serialization;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.NewCookie;
import java.util.List;

/**
 * @author Ryan Heaton
 */
public class TestUsernamePasswordFlow extends TestCase {

  /**
   * tests a happy-day flow of the username/password flow.
   */
  public void testUsernamePasswordHappyDay() throws Exception {
    int port = 8080;
    Client client = Client.create();
    client.setFollowRedirects(false);

    MultivaluedMap<String, String> formData = new MultivaluedMapImpl();
    formData.add("type", "username");
    formData.add("client_id", "my-trusted-client");
    formData.add("username", "marissa");
    formData.add("password", "koala");
    ClientResponse response = client.resource("http://localhost:" + port + "/sparklr2/oauth/authorize")
      .type(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
      .post(ClientResponse.class, formData);
    assertEquals(200, response.getClientResponseStatus().getStatusCode());
    assertEquals("no-store", response.getHeaders().getFirst("Cache-Control"));

    DefaultOAuth2SerializationService serializationService = new DefaultOAuth2SerializationService();
    OAuth2Serialization serialization = new OAuth2Serialization();
    serialization.setMediaType(response.getType().getType());
    serialization.setSerializedForm(response.getEntity(String.class));
    OAuth2AccessToken accessToken = serializationService.deserializeAccessToken(serialization);

    //now try and use the token to access a protected resource.

    //first make sure the resource is actually protected.
    response = client.resource("http://localhost:" + port + "/sparklr2/json/photos").get(ClientResponse.class);
    assertFalse(200 == response.getClientResponseStatus().getStatusCode());

    //now make sure an authorized request is valid.
    response = client.resource("http://localhost:" + port + "/sparklr2/json/photos")
      .header("Authorization", String.format("Token token=\"%s\"", accessToken.getValue()))
      .get(ClientResponse.class);
    assertEquals(200, response.getClientResponseStatus().getStatusCode());
  }

  /**
   * tests an invalid flow
   */
  public void testInvalidFlow() throws Exception {
    int port = 8080;
    Client client = Client.create();
    client.setFollowRedirects(false);

    MultivaluedMap<String, String> formData = new MultivaluedMapImpl();
    formData.add("type", "web_server");
    formData.add("client_id", "my-trusted-client");
    formData.add("username", "marissa");
    formData.add("password", "koala");
    ClientResponse response = client.resource("http://localhost:" + port + "/sparklr2/oauth/authorize")
      .type(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
      .post(ClientResponse.class, formData);
    assertEquals(400, response.getClientResponseStatus().getStatusCode());
    List<NewCookie> newCookies = response.getCookies();
    if (!newCookies.isEmpty()) {
      fail("No cookies should be set. Found: " + newCookies.get(0).getName() + ".");
    }
    assertEquals("no-store", response.getHeaders().getFirst("Cache-Control"));
  }
}
