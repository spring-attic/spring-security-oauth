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

package org.springframework.security.oauth2.config;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedMap;
import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.InMemoryClientDetailsService;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

import java.util.*;

/**
 * @author Ryan Heaton
 * @author Andrew McCall
 */
public class ClientDetailsServiceBeanDefinitionParser extends AbstractSingleBeanDefinitionParser {

  @Override
  protected Class getBeanClass(Element element) {
    return InMemoryClientDetailsService.class;
  }

  @Override
  protected void doParse(Element element, ParserContext parserContext, BeanDefinitionBuilder builder) {
    List clientElements = DomUtils.getChildElementsByTagName(element, "client");
    ManagedMap<String, BeanMetadataElement> clients = new ManagedMap<String, BeanMetadataElement>();
    for (Object item : clientElements) {
      BeanDefinitionBuilder client = BeanDefinitionBuilder.rootBeanDefinition(BaseClientDetails.class);
      Element clientElement = (Element) item;
      String clientId = clientElement.getAttribute("clientId");
      if (StringUtils.hasText(clientId)) {
        client.addPropertyValue("clientId", clientId);
      }
      else {
        parserContext.getReaderContext().error("A client id must be supplied with the definition of a client.", clientElement);
      }

      String secret = clientElement.getAttribute("secret");
      if (StringUtils.hasText(secret)) {
        client.addPropertyValue("clientSecret", secret);
      }
      String resourceIds = clientElement.getAttribute("resource-ids");
      if (StringUtils.hasText(clientId)) {
          client.addConstructorArgValue(resourceIds);
      }
      else {
    	  client.addConstructorArgValue("");
      }
      client.addConstructorArgValue(clientElement.getAttribute("scope"));
      client.addConstructorArgValue(clientElement.getAttribute("authorizedGrantTypes"));
      client.addConstructorArgValue(clientElement.getAttribute("authorities"));

      clients.put(clientId, client.getBeanDefinition());
    }

    builder.addPropertyValue("clientDetailsStore", clients);
  }
}