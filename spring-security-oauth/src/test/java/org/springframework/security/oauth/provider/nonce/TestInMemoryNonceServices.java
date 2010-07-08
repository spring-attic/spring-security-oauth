package org.springframework.security.oauth.provider.nonce;

import junit.framework.TestCase;
import org.springframework.security.oauth.provider.BaseConsumerDetails;

import java.util.UUID;

/**
 * @author Ryan Heaton
 */
public class TestInMemoryNonceServices extends TestCase {

  // seconds since epoch
  final long timestampForFirstRequest = System.currentTimeMillis() / 1000;

  @Override
  protected void setUp() throws Exception {
    InMemoryNonceServices.TIMESTAMP_ENTRIES.clear();
  }

  public void testValidateNonceSecondRequestWithNewTimestampJustBefore() {
    final InMemoryNonceServices nonceServices = new InMemoryNonceServices();
    final BaseConsumerDetails consumerDetails = new BaseConsumerDetails();
    consumerDetails.setConsumerKey("foo");
    String nonce = UUID.randomUUID().toString();
    nonceServices.validateNonce(consumerDetails,
                                this.timestampForFirstRequest - 15, nonce);
    nonce = UUID.randomUUID().toString();
    nonceServices.validateNonce(consumerDetails,
                                this.timestampForFirstRequest - 20, nonce);
    // The list of entires should only contain two timestamps.
    assertEquals(2, InMemoryNonceServices.TIMESTAMP_ENTRIES.get("foo")
      .size());
  }

  public void testValidateNonceSecondRequestWithSameTimestamp() {
    final InMemoryNonceServices nonceServices = new InMemoryNonceServices();
    final BaseConsumerDetails consumerDetails = new BaseConsumerDetails();
    consumerDetails.setConsumerKey("foo");
    String nonce = UUID.randomUUID().toString();
    nonceServices.validateNonce(consumerDetails,
                                this.timestampForFirstRequest + 10, nonce);
    nonce = UUID.randomUUID().toString();
    nonceServices.validateNonce(consumerDetails,
                                this.timestampForFirstRequest + 10, nonce);
    // The list of entires should only contain one timestamp.
    assertEquals(1, nonceServices.TIMESTAMP_ENTRIES.get("foo")
      .size());
  }

  public void testValidateNonceSecondRequestWithNewTimestampJustAfter() {
    final InMemoryNonceServices nonceServices = new InMemoryNonceServices();
    final BaseConsumerDetails consumerDetails = new BaseConsumerDetails();
    consumerDetails.setConsumerKey("foo");
    String nonce = UUID.randomUUID().toString();
    nonceServices.validateNonce(consumerDetails,
                                this.timestampForFirstRequest, nonce);
    nonce = UUID.randomUUID().toString();
    nonceServices.validateNonce(consumerDetails,
                                this.timestampForFirstRequest + 5, nonce);
    // A ConcurrentModificationException should not be thrown.
    assertTrue(true);
    // The list of entires should only contain two timestamps.
    assertEquals(2, nonceServices.TIMESTAMP_ENTRIES.get("foo")
      .size());
  }

}
