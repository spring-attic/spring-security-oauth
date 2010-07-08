/*
 * Copyright 2008-2009 Web Cohesion
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

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.method.AbstractFallbackMethodSecurityMetadataSource;
import org.springframework.core.annotation.AnnotationUtils;

import java.util.Collection;
import java.util.ArrayList;
import java.util.List;
import java.lang.reflect.Method;
import java.lang.annotation.Annotation;

/**
 * @author Ryan Heaton
 * @author Andrew McCall
 */
public class ConsumerSecurityMetadataSource extends AbstractFallbackMethodSecurityMetadataSource {

  protected List<ConfigAttribute> findAttributes(Class<?> clazz) {
    return processAnnotations(clazz.getAnnotations());
  }

  protected List<ConfigAttribute> findAttributes(Method method, Class<?> targetClass) {
    return processAnnotations(AnnotationUtils.getAnnotations(method));
  }

  public Collection<ConfigAttribute> getAllConfigAttributes() {
    return null;
  }

  private List<ConfigAttribute> processAnnotations(Annotation[] annotations) {
    if (annotations == null || annotations.length == 0) {
      return null;
    }
    List<ConfigAttribute> attributes = new ArrayList<ConfigAttribute>();

    // Process DenyAll, Permit all, then Roles, then Keys

    for (Annotation a : annotations) {
      if (a instanceof DenyAllConsumers) {
        attributes.add(ConsumerSecurityConfig.DENY_ALL_ATTRIBUTE);
        return attributes;
      }
      if (a instanceof PermitAllConsumers) {
        attributes.add(ConsumerSecurityConfig.PERMIT_ALL_ATTRIBUTE);
        return attributes;
      }
      if (a instanceof ConsumerRolesAllowed) {
        ConsumerRolesAllowed ra = (ConsumerRolesAllowed) a;
        for (String role : ra.value()) {
          attributes.add(new ConsumerSecurityConfig(role, ConsumerSecurityConfig.ConsumerSecurityType.CONSUMER_ROLE));
        }
        return attributes;
      }
      if (a instanceof ConsumerKeysAllowed) {
        ConsumerKeysAllowed ka = (ConsumerKeysAllowed) a;
        for (String key : ka.value()) {
          attributes.add(new ConsumerSecurityConfig(key, ConsumerSecurityConfig.ConsumerSecurityType.CONSUMER_KEY));
        }
        return attributes;
      }
    }
    return null;


  }

}
