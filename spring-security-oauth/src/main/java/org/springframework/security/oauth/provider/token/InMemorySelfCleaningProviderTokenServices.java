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

package org.springframework.security.oauth.provider.token;

import org.springframework.beans.factory.DisposableBean;

import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Implementation of TokenServices that stores tokens in memory. The token services will schedule a thread to do cleaning up of expired tokens.
 *
 * @author Ryan Heaton
 */
public class InMemorySelfCleaningProviderTokenServices extends InMemoryProviderTokenServices implements DisposableBean {

  private ScheduledExecutorService scheduler;
  private Integer cleanupIntervalSeconds;

  @Override
  public void afterPropertiesSet() throws Exception {
    super.afterPropertiesSet();

    if (cleanupIntervalSeconds == null) {
      cleanupIntervalSeconds = 60 * 60;
    }

    if (cleanupIntervalSeconds > 0) {
      scheduler = Executors.newSingleThreadScheduledExecutor();
      Runnable cleanupLogic = new Runnable() {
        public void run() {
          Iterator<Map.Entry<String, OAuthProviderTokenImpl>> entriesIt = tokenStore.entrySet().iterator();
          while (entriesIt.hasNext()) {
            Map.Entry<String, OAuthProviderTokenImpl> entry = entriesIt.next();
            OAuthProviderTokenImpl tokenImpl = entry.getValue();
            if (isExpired(tokenImpl)) {
              //there's a race condition here, but we'll live with it for now.
              entriesIt.remove();
              onTokenRemoved(tokenImpl);
            }
          }
        }
      };
      scheduler.scheduleAtFixedRate(cleanupLogic, getAccessTokenValiditySeconds(), cleanupIntervalSeconds, TimeUnit.SECONDS);
    }
  }

  public void destroy() throws Exception {
    if (scheduler != null) {
      scheduler.shutdownNow();
    }
  }

  /**
   * The interval at which to schedule cleanup. (&lt;= 0 for never).
   *
   * @return The interval at which to schedule cleanup.
   */
  public Integer getCleanupIntervalSeconds() {
    return cleanupIntervalSeconds;
  }

  /**
   * The interval at which to schedule cleanup.
   *
   * @param cleanupIntervalSeconds The interval at which to schedule cleanup.
   */
  public void setCleanupIntervalSeconds(Integer cleanupIntervalSeconds) {
    this.cleanupIntervalSeconds = cleanupIntervalSeconds;
  }
}