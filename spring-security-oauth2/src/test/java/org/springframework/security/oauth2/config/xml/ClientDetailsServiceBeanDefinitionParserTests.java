package org.springframework.security.oauth2.config.xml;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.util.Collection;
import java.util.Set;

import static org.junit.Assert.*;

@ContextConfiguration
@RunWith ( SpringJUnit4ClassRunner.class )
public class ClientDetailsServiceBeanDefinitionParserTests {

	@Autowired
	private ClientDetailsService clientDetailsService;

	@Test
	public void testClientDetailsFromNonPropertyFile() {

		// valid client details NOT from property file
		ClientDetails clientDetails = clientDetailsService.loadClientByClientId("my-client-id-non-property-file");
		assertNotNull(clientDetailsService);
		assertEquals("my-client-id-non-property-file", clientDetails.getClientId());
		assertEquals("my-client-secret-non-property-file", clientDetails.getClientSecret());

		Set<String> grantTypes = clientDetails.getAuthorizedGrantTypes();
		assertNotNull(grantTypes);
		assertEquals(2, grantTypes.size());
		assertTrue(grantTypes.contains("password"));
		assertTrue(grantTypes.contains("authorization_code"));

		Set<String> scopes = clientDetails.getScope();
		assertNotNull(scopes);
		assertEquals(2, scopes.size());
		assertTrue(scopes.contains("scope1"));
		assertTrue(scopes.contains("scope2"));

		Collection<GrantedAuthority> authorities = clientDetails.getAuthorities();
		assertNotNull(authorities);
		assertEquals(2, authorities.size());
		assertTrue(AuthorityUtils.authorityListToSet(authorities).contains("ROLE_USER"));
		assertTrue(AuthorityUtils.authorityListToSet(authorities).contains("ROLE_ANONYMOUS"));
	}

	@Test
	public void testClientDetailsFromPropertyFile() {

		// valid client details from property file
		ClientDetails clientDetails = clientDetailsService.loadClientByClientId("my-client-id-property-file");
		assertNotNull(clientDetailsService);
		assertEquals("my-client-id-property-file", clientDetails.getClientId());
		assertEquals("my-client-secret-property-file", clientDetails.getClientSecret());

		Set<String> grantTypes = clientDetails.getAuthorizedGrantTypes();
		assertNotNull(grantTypes);
		assertEquals(2, grantTypes.size());
		assertTrue(grantTypes.contains("password"));
		assertTrue(grantTypes.contains("authorization_code"));

		Set<String> scopes = clientDetails.getScope();
		assertNotNull(scopes);
		assertEquals(2, scopes.size());
		assertTrue(scopes.contains("scope1"));
		assertTrue(scopes.contains("scope2"));

		Collection<GrantedAuthority> authorities = clientDetails.getAuthorities();
		assertNotNull(authorities);
		assertEquals(2, authorities.size());
		assertTrue(AuthorityUtils.authorityListToSet(authorities).contains("ROLE_USER"));
		assertTrue(AuthorityUtils.authorityListToSet(authorities).contains("ROLE_ANONYMOUS"));
	}

	@Test
	public void testClientDetailsDefaultFlow() {
		ClientDetails clientDetails = clientDetailsService.loadClientByClientId("my-client-id-default-flow");
		assertNotNull(clientDetailsService);
		assertEquals("my-client-id-default-flow", clientDetails.getClientId());
		assertEquals(1, clientDetails.getRegisteredRedirectUri().size());
		assertEquals("http://mycompany.com", clientDetails.getRegisteredRedirectUri().iterator().next());

		Set<String> grantTypes = clientDetails.getAuthorizedGrantTypes();
		assertNotNull(grantTypes);
		assertEquals(2, grantTypes.size());
		assertTrue(grantTypes.contains("authorization_code"));
		assertTrue(grantTypes.contains("refresh_token"));
	}

}
