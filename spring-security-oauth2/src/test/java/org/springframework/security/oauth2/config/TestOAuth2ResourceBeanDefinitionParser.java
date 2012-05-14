package org.springframework.security.oauth2.config;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitResourceDetails;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@ContextConfiguration
@RunWith(SpringJUnit4ClassRunner.class)
public class TestOAuth2ResourceBeanDefinitionParser {

	@Autowired
	@Qualifier("one")
	private OAuth2ProtectedResourceDetails one;

	@Autowired
	@Qualifier("two")
	private OAuth2ProtectedResourceDetails two;

	@Autowired
	@Qualifier("three")
	private AuthorizationCodeResourceDetails three;

	@Autowired
	@Qualifier("four")
	private ImplicitResourceDetails four;
	
	@Test
	public void testResourceFromNonPropertyFile() {
		assertEquals("my-client-id-non-property-file", one.getClientId());
		assertEquals("my-client-secret-non-property-file", one.getClientSecret());
		assertEquals("http://somewhere.com", one.getAccessTokenUri());
		assertEquals(2, one.getScope().size());
		assertEquals("[none, some]", one.getScope().toString());
	}

	@Test
	public void testResourceFromPropertyFile() {
		assertEquals("my-client-id-property-file", two.getClientId());
		assertEquals("my-client-secret-property-file", two.getClientSecret());
		assertEquals("http://myhost.com", two.getAccessTokenUri());
		assertEquals(2, two.getScope().size());
		assertEquals("[none, all]", two.getScope().toString());
	}

	@Test
	public void testResourceWithRedirectUri() {
		assertEquals("my-client-id", three.getClientId());
		assertNull(three.getClientSecret());
		assertEquals("http://somewhere.com", three.getAccessTokenUri());
		assertEquals("http://anywhere.com", three.getPreEstablishedRedirectUri());
		assertFalse(three.isUseCurrentUri());
	}

	@Test
	public void testResourceWithImplicitGrant() {
		assertEquals("my-client-id", four.getClientId());
		assertNull(four.getClientSecret());
		assertEquals("http://somewhere.com", four.getAccessTokenUri());
	}

}
