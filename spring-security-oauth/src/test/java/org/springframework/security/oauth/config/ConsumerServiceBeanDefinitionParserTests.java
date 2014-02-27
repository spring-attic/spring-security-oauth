package org.springframework.security.oauth.config;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth.common.signature.SharedConsumerSecret;
import org.springframework.security.oauth.provider.ConsumerDetails;
import org.springframework.security.oauth.provider.ConsumerDetailsService;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@ContextConfiguration
@RunWith(SpringJUnit4ClassRunner.class)
public class ConsumerServiceBeanDefinitionParserTests {

	@Autowired
	private ConsumerDetailsService clientDetailsService;

	@Test
	public void testClientDetailsFromNonPropertyFile() {
		assertNotNull(clientDetailsService.loadConsumerByConsumerKey("www.google.com"));
	}

	@Test
	public void testClientDetailsFromPropertyFile() {
		ConsumerDetails consumer = clientDetailsService.loadConsumerByConsumerKey("my-client-key");
		assertNotNull(consumer);
		assertEquals("my-client-secret", ((SharedConsumerSecret)consumer.getSignatureSecret()).getConsumerSecret());
	}

}
