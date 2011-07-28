package org.springframework.security.oauth.provider.nonce;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.UUID;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth.provider.BaseConsumerDetails;

/**
 * @author Ryan Heaton
 */
public class TestInMemoryNonceServices {

	// seconds since epoch
	final long timestampForFirstRequest = System.currentTimeMillis() / 1000;

	@Before
	public void setUp() throws Exception {
		InMemoryNonceServices.TIMESTAMP_ENTRIES.clear();
	}

	@Test
	public void testValidateNonceSecondRequestWithNewTimestampJustBefore() {
		final InMemoryNonceServices nonceServices = new InMemoryNonceServices();
		final BaseConsumerDetails consumerDetails = new BaseConsumerDetails();
		consumerDetails.setConsumerKey("foo");
		String nonce = UUID.randomUUID().toString();
		nonceServices.validateNonce(consumerDetails, this.timestampForFirstRequest - 15, nonce);
		nonce = UUID.randomUUID().toString();
		nonceServices.validateNonce(consumerDetails, this.timestampForFirstRequest - 20, nonce);
		// The list of entires should only contain two timestamps.
		assertEquals(2, InMemoryNonceServices.TIMESTAMP_ENTRIES.get("foo").size());
	}

	@Test
	public void testValidateNonceSecondRequestWithSameTimestamp() {
		final InMemoryNonceServices nonceServices = new InMemoryNonceServices();
		final BaseConsumerDetails consumerDetails = new BaseConsumerDetails();
		consumerDetails.setConsumerKey("foo");
		String nonce = UUID.randomUUID().toString();
		nonceServices.validateNonce(consumerDetails, this.timestampForFirstRequest + 10, nonce);
		nonce = UUID.randomUUID().toString();
		nonceServices.validateNonce(consumerDetails, this.timestampForFirstRequest + 10, nonce);
		// The list of entires should only contain one timestamp.
		assertEquals(1, InMemoryNonceServices.TIMESTAMP_ENTRIES.get("foo").size());
	}

	@Test
	public void testValidateNonceSecondRequestWithNewTimestampJustAfter() {
		final InMemoryNonceServices nonceServices = new InMemoryNonceServices();
		final BaseConsumerDetails consumerDetails = new BaseConsumerDetails();
		consumerDetails.setConsumerKey("foo");
		String nonce = UUID.randomUUID().toString();
		nonceServices.validateNonce(consumerDetails, this.timestampForFirstRequest, nonce);
		nonce = UUID.randomUUID().toString();
		nonceServices.validateNonce(consumerDetails, this.timestampForFirstRequest + 5, nonce);
		// A ConcurrentModificationException should not be thrown.
		assertTrue(true);
		// The list of entires should only contain two timestamps.
		assertEquals(2, InMemoryNonceServices.TIMESTAMP_ENTRIES.get("foo").size());
	}

}
