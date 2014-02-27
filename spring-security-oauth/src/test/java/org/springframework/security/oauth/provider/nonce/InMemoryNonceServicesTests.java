package org.springframework.security.oauth.provider.nonce;

import static org.junit.Assert.assertEquals;

import java.util.UUID;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.oauth.provider.BaseConsumerDetails;
import org.springframework.security.oauth.provider.ConsumerDetails;

/**
 * @author Ryan Heaton
 * @author Jilles van Gurp
 */
public class InMemoryNonceServicesTests {

	private long now;
	private final InMemoryNonceServices nonceServices = new InMemoryNonceServices();

	@Before
	public void setUp() throws Exception {
		// seconds since epoch, reset for every test
		now = System.currentTimeMillis() / 1000;
		nonceServices.setValidityWindowSeconds(10);
		InMemoryNonceServices.NONCES.clear();
	}

	@Test
	public void shouldAcceptSameNonceWithDifferentTimestamp() {
		String nonce = nonce();
		nonceServices.validateNonce(consumer("foo"), now, nonce);
		nonceServices.validateNonce(consumer("foo"), now+5, nonce);
		assertEquals(2, InMemoryNonceServices.NONCES.size());
	}

	@Test(expected=NonceAlreadyUsedException.class)
	public void shouldRejectAlreadyUsedNonceWithSameTimestamp() {
		String nonce = nonce();
		nonceServices.validateNonce(consumer("foo"), now, nonce);
		nonceServices.validateNonce(consumer("foo"), now, nonce);
	}

	@Test(expected=CredentialsExpiredException.class)
	public void shouldRejectTooOldTimestamp() {
		nonceServices.validateNonce(consumer("foo"), now-11, nonce());
	}

	@Test
	public void shouldAcceptSameNonceFromDifferentConsumers() {
		String nonce = nonce();
		nonceServices.validateNonce(consumer("foo"), now, nonce);
		nonceServices.validateNonce(consumer("bar"), now, nonce);
		assertEquals(2, InMemoryNonceServices.NONCES.size());
	}

	@Test
	public void shouldRemoveOldNonces() {
		// order should not matter
		InMemoryNonceServices.NONCES.add(new InMemoryNonceServices.NonceEntry("foo", now-2, nonce()));
		InMemoryNonceServices.NONCES.add(new InMemoryNonceServices.NonceEntry("foo", now-11, nonce()));
		InMemoryNonceServices.NONCES.add(new InMemoryNonceServices.NonceEntry("foo", now+8, nonce()));
		InMemoryNonceServices.NONCES.add(new InMemoryNonceServices.NonceEntry("foo", now-15, nonce()));
		assertEquals(4, InMemoryNonceServices.NONCES.size());
		nonceServices.validateNonce(consumer("foo"), now, nonce());
		assertEquals("should have removed two from the original four nonces and added one",3, InMemoryNonceServices.NONCES.size());
	}

	private String nonce() {
		return UUID.randomUUID().toString();
	}

	private ConsumerDetails consumer(String name) {
		BaseConsumerDetails details = new BaseConsumerDetails();
		details.setConsumerKey(name);
		return details;
	}
}
