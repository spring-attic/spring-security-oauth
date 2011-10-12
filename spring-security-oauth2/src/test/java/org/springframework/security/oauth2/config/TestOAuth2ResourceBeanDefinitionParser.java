package org.springframework.security.oauth2.config;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
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

}
