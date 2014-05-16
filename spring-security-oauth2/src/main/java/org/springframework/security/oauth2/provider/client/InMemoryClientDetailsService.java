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

package org.springframework.security.oauth2.provider.client;

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.NoSuchClientException;

/**
 * Basic, in-memory implementation of the client details service.
 *
 * @author Ryan Heaton
 */
public class InMemoryClientDetailsService implements ClientDetailsService {

  private Map<String, ClientDetails> clientDetailsStore = new HashMap<String, ClientDetails>();

  public ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
    ClientDetails details = clientDetailsStore.get(clientId);
    if (details == null) {
      throw new NoSuchClientException("No client with requested id: " + clientId);
    }
    return details;
  }

  public void setClientDetailsStore(Map<String, ? extends ClientDetails> clientDetailsStore) {
    this.clientDetailsStore = new HashMap<String, ClientDetails>(clientDetailsStore);
  }

}