package org.springframework.security.oauth2.config.xml;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitResourceDetails;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@ContextConfiguration
@RunWith(SpringJUnit4ClassRunner.class)
public class ResourceBeanDefinitionParserTests {

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
	
	@Autowired
	@Qualifier("five")
	private ClientCredentialsResourceDetails five;
	
	@Autowired
	@Qualifier("six")
	private AuthorizationCodeResourceDetails six;

	@Autowired
	@Qualifier("seven")
	private ResourceOwnerPasswordResourceDetails seven;

	@Autowired
	@Qualifier("template")
	private OAuth2RestTemplate template;
	
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
		assertEquals("http://somewhere.com", four.getUserAuthorizationUri());
	}

	@Test
	public void testResourceWithClientCredentialsGrant() {
		assertEquals("my-secret-id", five.getClientId());
		assertEquals("secret", five.getClientSecret());
		assertEquals("http://somewhere.com", five.getAccessTokenUri());
		assertNotNull(template.getOAuth2ClientContext().getAccessTokenRequest());
	}

	@Test
	public void testResourceWithCurrentUriHint() {
		assertEquals("my-client-id", six.getClientId());
		assertFalse(six.isUseCurrentUri());
		assertEquals(AuthenticationScheme.form, six.getClientAuthenticationScheme());
	}

	@Test
	public void testResourceWithPasswordGrant() {
		assertEquals("my-client-id", seven.getClientId());
		assertEquals("secret", seven.getClientSecret());
		assertEquals("http://somewhere.com", seven.getAccessTokenUri());
		assertEquals("admin", seven.getUsername());
		assertEquals("long-and-strong", seven.getPassword());
	}
}
