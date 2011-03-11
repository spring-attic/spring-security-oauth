package org.springframework.security.oauth2.provider;

import com.gargoylesoftware.htmlunit.BrowserVersion;
import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlSubmitInput;
import com.gargoylesoftware.htmlunit.html.HtmlTextInput;
import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.core.util.MultivaluedMapImpl;
import junit.framework.TestCase;
import org.springframework.security.oauth2.common.DefaultOAuth2SerializationService;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.UriBuilder;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.util.StringTokenizer;

/**
 * @author Ryan Heaton
 */
public class TestWebServerProfile extends TestCase {

  /**
   * tests the basic web server profile
   */
  public void testBasicWebServerProfile() throws Exception {
    int port = 8080;

    WebClient userAgent = new WebClient(BrowserVersion.FIREFOX_3);
    userAgent.setRedirectEnabled(false);
    UriBuilder uriBuilder = UriBuilder.fromUri("http://localhost:" + port + "/sparklr/oauth/user/authorize")
      .queryParam("response_type", "code")
      .queryParam("state", "mystateid")
      .queryParam("client_id", "my-less-trusted-client")
      .queryParam("redirect_uri", "http://anywhere");
    String location = null;
    try {
      userAgent.getPage(uriBuilder.build().toURL());
      fail("should have been redirected to the login form.");
    }
    catch (FailingHttpStatusCodeException e) {
      location = e.getResponse().getResponseHeaderValue("Location");
    }

    HtmlPage loginPage = userAgent.getPage(location);
    //should be directed to the login screen...
    HtmlForm loginForm = loginPage.getFormByName("loginForm");
    ((HtmlTextInput)loginForm.getInputByName("j_username")).setValueAttribute("marissa");
    ((HtmlTextInput)loginForm.getInputByName("j_password")).setValueAttribute("koala");
    try {
      ((HtmlSubmitInput)loginForm.getInputByName("login")).click();
      fail("should have been redirected to the authorization endpoint.");
    }
    catch (FailingHttpStatusCodeException e) {
      location = e.getResponse().getResponseHeaderValue("Location");
    }

    try {
      userAgent.getPage(location);
      fail("should have been redirected to the confirmation page.");
    }
    catch (FailingHttpStatusCodeException e) {
      location = e.getResponse().getResponseHeaderValue("Location");
    }

    HtmlPage confirmationPage = userAgent.getPage(location);
    HtmlForm okForm = confirmationPage.getFormByName("confirmationForm");
    try {
      ((HtmlSubmitInput)okForm.getInputByName("authorize")).click();
    }
    catch (FailingHttpStatusCodeException e) {
      location = e.getResponse().getResponseHeaderValue("Location");
    }

    URI redirection = UriBuilder.fromUri(location).build();
    assertEquals("anywhere", redirection.getHost());
    assertEquals("http", redirection.getScheme());
    assertNotNull(redirection.getQuery());

    String code = null;
    String state = null;
    for (StringTokenizer queryTokens = new StringTokenizer(redirection.getQuery(), "&="); queryTokens.hasMoreTokens();) {
      String token = queryTokens.nextToken();
      if ("code".equals(token)) {
        if (code != null) {
          fail("shouldn't have returned more than one code.");
        }

        code = queryTokens.nextToken();
      }
      else if ("state".equals(token)) {
        state = queryTokens.nextToken();
      }
    }

    assertEquals("mystateid", state);
    assertNotNull(code);

    //we've got the verification code. now we should be able to get an access token.
    Client client = Client.create();
    client.setFollowRedirects(false);
    MultivaluedMap<String, String> formData = new MultivaluedMapImpl();
    formData.add("grant_type", "authorization_code");
    formData.add("client_id", "my-less-trusted-client");
    formData.add("redirect_uri", "http://anywhere");
    formData.add("code", code);
    ClientResponse response = client.resource("http://localhost:" + port + "/sparklr/oauth/authorize")
      .type(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
      .post(ClientResponse.class, formData);
    assertEquals(200, response.getClientResponseStatus().getStatusCode());
    assertEquals("no-store", response.getHeaders().getFirst("Cache-Control"));

    DefaultOAuth2SerializationService serializationService = new DefaultOAuth2SerializationService();
    OAuth2AccessToken accessToken = serializationService.deserializeJsonAccessToken(response.getEntityInputStream());

    //let's try that request again and make sure we can't re-use the verification code...
    response = client.resource("http://localhost:" + port + "/sparklr/oauth/authorize")
      .type(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
      .post(ClientResponse.class, formData);
    assertEquals(401, response.getClientResponseStatus().getStatusCode());
    assertEquals("no-store", response.getHeaders().getFirst("Cache-Control"));
    try {
      throw serializationService.deserializeJsonError(new ByteArrayInputStream(response.getEntity(String.class).getBytes("UTF-8")));
    }
    catch (OAuth2Exception e) {
      assertTrue(e instanceof InvalidGrantException);
    }

    //now try and use the token to access a protected resource.

    //first make sure the resource is actually protected.
    response = client.resource("http://localhost:" + port + "/sparklr/json/photos").get(ClientResponse.class);
    assertFalse(200 == response.getClientResponseStatus().getStatusCode());
    String authHeader = response.getHeaders().getFirst("WWW-Authenticate");
    assertNotNull(authHeader);
    assertTrue(authHeader.startsWith("OAuth2"));

    //now make sure an authorized request is valid.
    response = client.resource("http://localhost:" + port + "/sparklr/json/photos")
      .header("Authorization", String.format("OAuth2 %s", accessToken.getValue()))
      .get(ClientResponse.class);
    assertEquals(200, response.getClientResponseStatus().getStatusCode());
  }

  /**
   * tests failure of getting the access token if some params are missing
   */
  public void testFailureIfSomeParametersAreMissing() throws Exception {
    int port = 8080;

    WebClient userAgent = new WebClient(BrowserVersion.FIREFOX_3);
    userAgent.setRedirectEnabled(false);
    UriBuilder uriBuilder = UriBuilder.fromUri("http://localhost:" + port + "/sparklr/oauth/user/authorize")
      .queryParam("response_type", "code")
      .queryParam("state", "mystateid")
      .queryParam("client_id", "my-less-trusted-client")
      .queryParam("redirect_uri", "http://anywhere");
    String location = null;
    try {
      userAgent.getPage(uriBuilder.build().toURL());
      fail("should have been redirected to the login form.");
    }
    catch (FailingHttpStatusCodeException e) {
      location = e.getResponse().getResponseHeaderValue("Location");
    }

    HtmlPage loginPage = userAgent.getPage(location);
    //should be directed to the login screen...
    HtmlForm loginForm = loginPage.getFormByName("loginForm");
    ((HtmlTextInput)loginForm.getInputByName("j_username")).setValueAttribute("marissa");
    ((HtmlTextInput)loginForm.getInputByName("j_password")).setValueAttribute("koala");
    try {
      ((HtmlSubmitInput)loginForm.getInputByName("login")).click();
      fail("should have been redirected to the authorization endpoint.");
    }
    catch (FailingHttpStatusCodeException e) {
      location = e.getResponse().getResponseHeaderValue("Location");
    }

    try {
      userAgent.getPage(location);
      fail("should have been redirected to the confirmation page.");
    }
    catch (FailingHttpStatusCodeException e) {
      location = e.getResponse().getResponseHeaderValue("Location");
    }

    HtmlPage confirmationPage = userAgent.getPage(location);
    HtmlForm okForm = confirmationPage.getFormByName("confirmationForm");
    try {
      ((HtmlSubmitInput)okForm.getInputByName("authorize")).click();
    }
    catch (FailingHttpStatusCodeException e) {
      location = e.getResponse().getResponseHeaderValue("Location");
    }

    URI redirection = UriBuilder.fromUri(location).build();
    assertEquals("anywhere", redirection.getHost());
    assertEquals("http", redirection.getScheme());
    assertNotNull(redirection.getQuery());

    String code = null;
    for (StringTokenizer queryTokens = new StringTokenizer(redirection.getQuery(), "&="); queryTokens.hasMoreTokens();) {
      String token = queryTokens.nextToken();
      if ("code".equals(token)) {
        if (code != null) {
          fail("shouldn't have returned more than one code.");
        }

        code = queryTokens.nextToken();
      }
    }

    assertNotNull(code);

    //we've got the verification code. now let's make sure we get an error if we attempt to use a different redirect uri
    Client client = Client.create();
    client.setFollowRedirects(false);

    MultivaluedMap<String, String> formData = new MultivaluedMapImpl();
    formData.add("grant_type", "authorization_code");
    formData.add("client_id", "my-less-trusted-client");
    formData.add("redirect_uri", "http://nowhere");
    formData.add("code", code);
    ClientResponse response = client.resource("http://localhost:" + port + "/sparklr/oauth/authorize")
      .type(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
      .post(ClientResponse.class, formData);
    assertEquals(401, response.getClientResponseStatus().getStatusCode());
    assertEquals("no-store", response.getHeaders().getFirst("Cache-Control"));

    DefaultOAuth2SerializationService serializationService = new DefaultOAuth2SerializationService();
    try {
      throw serializationService.deserializeJsonError(response.getEntityInputStream());
    }
    catch (OAuth2Exception e) {
      assertTrue("should be a redirect uri mismatch", e instanceof RedirectMismatchException);
    }
  }

  /**
   * tests what happens if the user fails to authorize a token.
   */
  public void testUserFailsToAuthorize() throws Exception {
    int port = 8080;

    WebClient userAgent = new WebClient(BrowserVersion.FIREFOX_3);
    userAgent.setRedirectEnabled(false);
    UriBuilder uriBuilder = UriBuilder.fromUri("http://localhost:" + port + "/sparklr/oauth/user/authorize")
      .queryParam("response_type", "code")
      .queryParam("state", "mystateid")
      .queryParam("client_id", "my-less-trusted-client")
      .queryParam("redirect_uri", "http://anywhere");
    String location = null;
    try {
      userAgent.getPage(uriBuilder.build().toURL());
      fail("should have been redirected to the login form.");
    }
    catch (FailingHttpStatusCodeException e) {
      location = e.getResponse().getResponseHeaderValue("Location");
    }

    HtmlPage loginPage = userAgent.getPage(location);
    //should be directed to the login screen...
    HtmlForm loginForm = loginPage.getFormByName("loginForm");
    ((HtmlTextInput)loginForm.getInputByName("j_username")).setValueAttribute("marissa");
    ((HtmlTextInput)loginForm.getInputByName("j_password")).setValueAttribute("koala");
    try {
      ((HtmlSubmitInput)loginForm.getInputByName("login")).click();
      fail("should have been redirected to the authorization endpoint.");
    }
    catch (FailingHttpStatusCodeException e) {
      location = e.getResponse().getResponseHeaderValue("Location");
    }

    try {
      userAgent.getPage(location);
      fail("should have been redirected to the confirmation page.");
    }
    catch (FailingHttpStatusCodeException e) {
      location = e.getResponse().getResponseHeaderValue("Location");
    }

    HtmlPage confirmationPage = userAgent.getPage(location);
    HtmlForm nonoForm = confirmationPage.getFormByName("denialForm");
    try {
      ((HtmlSubmitInput)nonoForm.getInputByName("deny")).click();
    }
    catch (FailingHttpStatusCodeException e) {
      location = e.getResponse().getResponseHeaderValue("Location");
    }

    assertTrue(location.startsWith("http://anywhere"));
    assertTrue(location.substring(location.indexOf('?')).contains("error=access_denied"));
  }


  /**
   * tests what happens if the client id isn't provided.
   */
  public void testNoClientIdProvided() throws Exception {
    int port = 8080;

    WebClient userAgent = new WebClient(BrowserVersion.FIREFOX_3);
    userAgent.setRedirectEnabled(false);
    UriBuilder uriBuilder = UriBuilder.fromUri("http://localhost:" + port + "/sparklr/oauth/user/authorize")
      .queryParam("response_type", "code")
      .queryParam("state", "mystateid")
      //.queryParam("client_id", "my-less-trusted-client")
      .queryParam("redirect_uri", "http://anywhere");
    String location = null;
    try {
      userAgent.getPage(uriBuilder.build().toURL());
      fail("should have been redirected to the login form.");
    }
    catch (FailingHttpStatusCodeException e) {
      location = e.getResponse().getResponseHeaderValue("Location");
    }

    assertTrue(location.startsWith("http://anywhere"));
    assertTrue(location.substring(location.indexOf('?')).contains("error=invalid_client"));

    uriBuilder = UriBuilder.fromUri("http://localhost:" + port + "/sparklr/oauth/user/authorize")
      .queryParam("response_type", "code")
      .queryParam("state", "mystateid");
      //.queryParam("client_id", "my-less-trusted-client")
      //.queryParam("redirect_uri", "http://anywhere");
    try {
      userAgent.getPage(uriBuilder.build().toURL());
      fail("should have been redirected to the login form.");
    }
    catch (FailingHttpStatusCodeException e) {
      location = e.getResponse().getResponseHeaderValue("Location");
    }

    assertTrue(location.startsWith("http://localhost"));
  }

}
