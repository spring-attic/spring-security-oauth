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

package org.springframework.security.oauth.provider.attributes;

import org.springframework.security.access.SecurityConfig;

/**
 * Security config for consumer authorization of a method.
 * 
 * @author Ryan Heaton
 */
@SuppressWarnings("serial")
public class ConsumerSecurityConfig extends SecurityConfig {

  public static final ConsumerSecurityConfig DENY_ALL_ATTRIBUTE = new ConsumerSecurityConfig(DenyAllConsumers.class.getName(), null);
  public static final ConsumerSecurityConfig PERMIT_ALL_ATTRIBUTE = new ConsumerSecurityConfig(PermitAllConsumers.class.getName(), null);

  /**
   * Type of security.
   */
  public enum ConsumerSecurityType {

    /**
     * Consumer key type.
     */
    CONSUMER_KEY,

    /**
     * Consumer role type.
     */
    CONSUMER_ROLE

  }

  private final ConsumerSecurityType securityType;

  public ConsumerSecurityConfig(String config, ConsumerSecurityType type) {
    super(config);
    this.securityType = type;
  }

  public ConsumerSecurityType getSecurityType() {
    return securityType;
  }
}
