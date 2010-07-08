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

package org.springframework.security.oauth.consumer;

import java.util.Map;
import java.util.HashMap;

/**
 * Basic, in-memory implementation of a protected resource details service.
 *
 * @author Ryan Heaton
 */
public class InMemoryProtectedResourceDetailsService implements ProtectedResourceDetailsService {

  private Map<String, ? extends ProtectedResourceDetails> resourceDetailsStore = new HashMap<String, ProtectedResourceDetails>();

  public ProtectedResourceDetails loadProtectedResourceDetailsById(String id) throws IllegalArgumentException {
    return getResourceDetailsStore().get(id);
  }

  public Map<String, ? extends ProtectedResourceDetails> getResourceDetailsStore() {
    return resourceDetailsStore;
  }

  public void setResourceDetailsStore(Map<String, ? extends ProtectedResourceDetails> resourceDetailsStore) {
    this.resourceDetailsStore = resourceDetailsStore;
  }
}
