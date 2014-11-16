/*
 * Copyright 2008 Web Cohesion
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth.provider.nonce;

import java.util.Iterator;
import java.util.TreeSet;

import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.oauth.provider.ConsumerDetails;

/**
 * Expands on the {@link org.springframework.security.oauth.provider.nonce.ExpiringTimestampNonceServices} to include
 * validation of the nonce for replay protection.
 * 
 * To validate the nonce, the InMemoryNonceService first validates the consumer key and timestamp as does the
 * {@link org.springframework.security.oauth.provider.nonce.ExpiringTimestampNonceServices}. Assuming the consumer and
 * timestamp are valid, the InMemoryNonceServices further ensures that the specified nonce was not used with the
 * specified timestamp within the specified validity window. The list of nonces used within the validity window is kept
 * in memory.
 *
 * Note: the default validity window in this class is different from the one used in
 * {@link org.springframework.security.oauth.provider.nonce.ExpiringTimestampNonceServices}. The reason for this is that
 * this class has a per request memory overhead. Keeping the validity window short helps prevent wasting a lot of
 * memory. 10 minutes that allows for minor variations in time between servers.
 *
 * @author Ryan Heaton
 * @author Jilles van Gurp
 */
public class InMemoryNonceServices implements OAuthNonceServices {

	/**
	 * Contains all the nonces that were used inside the validity window.
	 */
	static final TreeSet<NonceEntry> NONCES = new TreeSet<NonceEntry>();

	private volatile long lastCleaned = 0;

	// we'll default to a 10 minute validity window, otherwise the amount of memory used on NONCES can get quite large.
	private long validityWindowSeconds = 60 * 10;

	public void validateNonce(ConsumerDetails consumerDetails, long timestamp, String nonce) {
		if (System.currentTimeMillis() / 1000 - timestamp > getValidityWindowSeconds()) {
			throw new CredentialsExpiredException("Expired timestamp.");
		}

		NonceEntry entry = new NonceEntry(consumerDetails.getConsumerKey(), timestamp, nonce);

		synchronized (NONCES) {
			if (NONCES.contains(entry)) {
				throw new NonceAlreadyUsedException("Nonce already used: " + nonce);
			}
			else {
				NONCES.add(entry);
			}
			cleanupNonces();
		}
	}

	private void cleanupNonces() {
		long now = System.currentTimeMillis() / 1000;
		// don't clean out the NONCES for each request, this would cause the service to be constantly locked on this
		// loop under load. One second is small enough that cleaning up does not become too expensive.
		// Also see SECOAUTH-180 for reasons this class was refactored.
		if (now - lastCleaned > 1) {
			Iterator<NonceEntry> iterator = NONCES.iterator();
			while (iterator.hasNext()) {
				// the nonces are already sorted, so simply iterate and remove until the first nonce within the validity
				// window.
				NonceEntry nextNonce = iterator.next();
				long difference = now - nextNonce.timestamp;
				if (difference > getValidityWindowSeconds()) {
					iterator.remove();
				}
				else {
					break;
				}
			}
			// keep track of when cleanupNonces last ran
			lastCleaned = now;
		}
	}

	/**
	 * Set the timestamp validity window (in seconds).
	 *
	 * @return the timestamp validity window (in seconds).
	 */
	public long getValidityWindowSeconds() {
		return validityWindowSeconds;
	}

	/**
	 * The timestamp validity window (in seconds).
	 *
	 * @param validityWindowSeconds the timestamp validity window (in seconds).
	 */
	public void setValidityWindowSeconds(long validityWindowSeconds) {
		this.validityWindowSeconds = validityWindowSeconds;
	}

	/**
	 * Representation of a nonce with the right hashCode, equals, and compareTo methods for the TreeSet approach above
	 * to work.
	 */
	static class NonceEntry implements Comparable<NonceEntry> {
		private final String consumerKey;

		private final long timestamp;

		private final String nonce;

		public NonceEntry(String consumerKey, long timestamp, String nonce) {
			this.consumerKey = consumerKey;
			this.timestamp = timestamp;
			this.nonce = nonce;
		}

		@Override
		public int hashCode() {
			return consumerKey.hashCode() * nonce.hashCode() * Long.valueOf(timestamp).hashCode();
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == null || !(obj instanceof NonceEntry)) {
				return false;
			}
			NonceEntry arg = (NonceEntry) obj;
			return timestamp == arg.timestamp && consumerKey.equals(arg.consumerKey) && nonce.equals(arg.nonce);
		}

		public int compareTo(NonceEntry o) {
			// sort by timestamp
			if (timestamp < o.timestamp) {
				return -1;
			}
			else if (timestamp == o.timestamp) {
				int consumerKeyCompare = consumerKey.compareTo(o.consumerKey);
				if (consumerKeyCompare == 0) {
					return nonce.compareTo(o.nonce);
				}
				else {
					return consumerKeyCompare;
				}
			}
			else {
				return 1;
			}
		}

		@Override
		public String toString() {
			return timestamp + " " + consumerKey + " " + nonce;
		}
	}
}
