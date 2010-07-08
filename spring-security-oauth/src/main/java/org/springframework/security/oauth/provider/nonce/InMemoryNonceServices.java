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

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth.provider.ConsumerDetails;

import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.*;

/**
 * Expands on the {@link org.springframework.security.oauth.provider.nonce.ExpiringTimestampNonceServices} to
 * include validation of the nonce for replay protection.<br/><br/>
 *
 * To validate the nonce, the InMemoryNonceService first validates the consumer key and timestamp as does the
 * {@link org.springframework.security.oauth.provider.nonce.ExpiringTimestampNonceServices}.  Assuming the consumer
 * and timestamp are valid, the InMemoryNonceServices further ensures that the specified nonce was not used with the
 * specified timestamp within the specified validity window.  The list of nonces used within the validity window
 * is kept in memory.<br/><br/>
 *
 * @author Ryan Heaton
 */
public class InMemoryNonceServices extends ExpiringTimestampNonceServices {

  protected static final ConcurrentMap<String, LinkedList<TimestampEntry>> TIMESTAMP_ENTRIES = new ConcurrentHashMap<String, LinkedList<TimestampEntry>>();

  @Override
  public void validateNonce(ConsumerDetails consumerDetails, long timestamp, String nonce) throws AuthenticationException {
    final long cutoff = (System.currentTimeMillis() / 1000) - getValidityWindowSeconds();
    super.validateNonce(consumerDetails, timestamp, nonce);

    String consumerKey = consumerDetails.getConsumerKey();
    LinkedList<TimestampEntry> entries = TIMESTAMP_ENTRIES.get(consumerKey);
    if (entries == null) {
      entries = new LinkedList<TimestampEntry>();
      TIMESTAMP_ENTRIES.put(consumerKey, entries);
    }

    synchronized (entries) {
      if (entries.isEmpty()) {
        entries.add(new TimestampEntry(timestamp, nonce));
      }
      else {
        boolean isNew = entries.getLast().getTimestamp() < timestamp;
        ListIterator<TimestampEntry> listIterator = entries.listIterator();
        while (listIterator.hasNext()) {
          TimestampEntry entry = listIterator.next();
          if (entry.getTimestamp() < cutoff) {
            listIterator.remove();
            isNew = !listIterator.hasNext();
          }
          else if (isNew) {
            //optimize for a new, latest timestamp
            entries.addLast(new TimestampEntry(timestamp, nonce));
            return;
          }
          else if (entry.getTimestamp() == timestamp) {
            if (!entry.addNonce(nonce)) {
              throw new NonceAlreadyUsedException("Nonce already used: " + nonce);
            }
            return;
          }
          else if (entry.getTimestamp() > timestamp) {
            //insert a new entry just before this one.
            entries.add(listIterator.previousIndex(), new TimestampEntry(timestamp, nonce));
            return;
          }
        }

        //got through the whole list; assume it's just a new one.
        //this shouldn't happen because of the optimization above.
        entries.addLast(new TimestampEntry(timestamp, nonce));
      }
    }
  }

  protected static class TimestampEntry {

    private final Long timestamp;
    private final Set<String> nonces = new HashSet<String>();

    public TimestampEntry(long timestamp, String firstNonce) {
      this.timestamp = timestamp;
      this.nonces.add(firstNonce);
    }

    /**
     * Adds a nonce to this timestamp entry.
     *
     * @param nonce The nonce to add.
     * @return The nonce.
     */
    public boolean addNonce(String nonce) {
      synchronized (nonces) {
        return nonces.add(nonce);
      }
    }

    /**
     * Get the timestamp for this entry.
     *
     * @return The timestamp for this entry.
     */
    public Long getTimestamp() {
      return timestamp;
    }

    @Override
    public int hashCode() {
      return timestamp.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
      return obj instanceof TimestampEntry && this.timestamp.equals(((TimestampEntry) obj).timestamp);
    }
  }
}
