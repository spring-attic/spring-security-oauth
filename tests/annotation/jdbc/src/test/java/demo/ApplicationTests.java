package demo;

import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.IntegrationTest;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = Application.class)
@WebAppConfiguration
@IntegrationTest("server.port=0")
public class ApplicationTests {
	
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
