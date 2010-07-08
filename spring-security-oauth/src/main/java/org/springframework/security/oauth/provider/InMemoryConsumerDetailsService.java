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

package org.springframework.security.oauth.provider;

import org.springframework.security.oauth.common.OAuthException;

import java.util.HashMap;
import java.util.Map;

/**
 * Basic, in-memory implementation of the consumer details service.
 *
 * @author Ryan Heaton
 */
public class InMemoryConsumerDetailsService implements ConsumerDetailsService {

  private Map<String, ? extends ConsumerDetails> consumerDetailsStore = new HashMap<String, ConsumerDetails>();

  public ConsumerDetails loadConsumerByConsumerKey(String consumerKey) throws OAuthException {
    ConsumerDetails details = consumerDetailsStore.get(consumerKey);
    if (details == null) {
      throw new InvalidOAuthParametersException("Consumer not found: " + consumerKey);
    }
    return details;
  }

  public Map<String, ? extends ConsumerDetails> getConsumerDetailsStore() {
    return consumerDetailsStore;
  }

  public void setConsumerDetailsStore(Map<String, ? extends ConsumerDetails> consumerDetailsStore) {
    this.consumerDetailsStore = consumerDetailsStore;
  }
}
