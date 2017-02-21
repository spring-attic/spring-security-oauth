package demo;

import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.test.context.ContextConfiguration;

import sparklr.common.AbstractIntegrationTests;

@ContextConfiguration(classes=Application.class)
public class ApplicationTests extends AbstractIntegrationTests {
	
	@Autowired
	private TokenStore tokenStore;

	@Autowired
	private ClientDetailsService clientDetailsService;

	@Test
	public void contextLoads() {
		assertTrue("Wrong token store type: " + tokenStore, tokenStore instanceof JdbcTokenStore);
		assertTrue("Wrong client details type: " + clientDetailsService, clientDetailsService.toString().contains(JdbcClientDetailsService.class.getName()));
	}

}
