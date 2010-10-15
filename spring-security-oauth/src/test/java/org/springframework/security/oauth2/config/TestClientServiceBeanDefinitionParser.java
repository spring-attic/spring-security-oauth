package org.springframework.security.oauth2.config;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit38.AbstractJUnit38SpringContextTests;

import java.util.List;

@ContextConfiguration({"/TestClientServiceBeanDefinitionParser-applicationContext.xml"})
public class TestClientServiceBeanDefinitionParser extends AbstractJUnit38SpringContextTests {

  public void testClientDetailsFromNonPropertyFile() {
    ClientDetailsService clientDetailsService = (ClientDetailsService) applicationContext.getBean("clientDetails");
    assertNotNull(clientDetailsService);

    // valid client details NOT from property file
    ClientDetails clientDetails = clientDetailsService.loadClientByClientId("my-client-id-non-property-file");
    assertNotNull(clientDetailsService);
    assertEquals("my-client-id-non-property-file", clientDetails.getClientId());
    assertEquals("my-client-secret-non-property-file", clientDetails.getClientSecret());

    List<String> grantTypes = clientDetails.getAuthorizedGrantTypes();
    assertNotNull(grantTypes);
    assertEquals(2, grantTypes.size());
    assertTrue(grantTypes.contains("password"));
    assertTrue(grantTypes.contains("authorization_code"));

    List<String> scopes = clientDetails.getScope();
    assertNotNull(scopes);
    assertEquals(2, scopes.size());
    assertTrue(scopes.contains("scope1"));
    assertTrue(scopes.contains("scope2"));

    List<GrantedAuthority> authorities = clientDetails.getAuthorities();
    assertNotNull(authorities);
    assertEquals(2, authorities.size());
    assertTrue(authorities.get(0).getAuthority().equals("ROLE_USER"));
    assertTrue(authorities.get(1).getAuthority().equals("ROLE_ANONYMOUS"));
  }

  public void testClientDetailsFromPropertyFile() {
    ClientDetailsService clientDetailsService = (ClientDetailsService) applicationContext.getBean("clientDetails");
    assertNotNull(clientDetailsService);

    // valid client details from property file
    ClientDetails clientDetails = clientDetailsService.loadClientByClientId("my-client-id-property-file");
    assertNotNull(clientDetailsService);
    assertEquals("my-client-id-property-file", clientDetails.getClientId());
    assertEquals("my-client-secret-property-file", clientDetails.getClientSecret());

    List<String> grantTypes = clientDetails.getAuthorizedGrantTypes();
    assertNotNull(grantTypes);
    assertEquals(2, grantTypes.size());
    assertTrue(grantTypes.contains("password"));
    assertTrue(grantTypes.contains("authorization_code"));

    List<String> scopes = clientDetails.getScope();
    assertNotNull(scopes);
    assertEquals(2, scopes.size());
    assertTrue(scopes.contains("scope1"));
    assertTrue(scopes.contains("scope2"));

    List<GrantedAuthority> authorities = clientDetails.getAuthorities();
    assertNotNull(authorities);
    assertEquals(2, authorities.size());
    assertTrue(authorities.get(0).getAuthority().equals("ROLE_USER"));
    assertTrue(authorities.get(1).getAuthority().equals("ROLE_ANONYMOUS"));
  }

  public void testClientDetailsDefaultFlow() {
    ClientDetailsService clientDetailsService = (ClientDetailsService) applicationContext.getBean("clientDetails");
    assertNotNull(clientDetailsService);

    ClientDetails clientDetails = clientDetailsService.loadClientByClientId("my-client-id-default-flow");
    assertNotNull(clientDetailsService);
    assertEquals("my-client-id-default-flow", clientDetails.getClientId());


    List<String> grantTypes = clientDetails.getAuthorizedGrantTypes();
    assertNotNull(grantTypes);
    assertEquals(1, grantTypes.size());
    assertTrue(grantTypes.contains("authorization_code"));
  }
}
