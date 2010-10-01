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

import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.core.authority.AuthorityUtils;
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
public class ClientServiceBeanDefinitionParser extends AbstractSingleBeanDefinitionParser {

  @Override
  protected Class getBeanClass(Element element) {
    return InMemoryClientDetailsService.class;
  }

  @Override
  protected void doParse(Element element, ParserContext parserContext, BeanDefinitionBuilder builder) {
    List clientElements = DomUtils.getChildElementsByTagName(element, "client");
    Map<String, BaseClientDetails> clients = new HashMap<String, BaseClientDetails>();
    for (Object item : clientElements) {
      BaseClientDetails client = new BaseClientDetails();
      Element clientElement = (Element) item;
      String clientId = clientElement.getAttribute("clientId");
      if (StringUtils.hasText(clientId)) {
        client.setClientId(clientId);
      }
      else {
        parserContext.getReaderContext().error("A client id must be supplied with the definition of a client.", clientElement);
      }

      String secret = clientElement.getAttribute("secret");
      if (StringUtils.hasText(secret)) {
        client.setClientSecret(secret);
      }

      String scope = clientElement.getAttribute("scope");
      if (StringUtils.hasText(scope)) {
        List<String> scopeList = new ArrayList<String>();
        for (StringTokenizer tokenizer = new StringTokenizer(scope, ","); tokenizer.hasMoreTokens();) {
          scopeList.add(tokenizer.nextToken().trim());
        }
        if (!scopeList.isEmpty()) {
          client.setScope(scopeList);
        }
      }

      String grantTypes = clientElement.getAttribute("authorizedGrantTypes");
      List<String> grantTypeList = new ArrayList<String>();
      if (StringUtils.hasText(grantTypes)) {
        for (StringTokenizer tokenizer = new StringTokenizer(grantTypes, ","); tokenizer.hasMoreTokens();) {
          grantTypeList.add(tokenizer.nextToken().trim());
        }
      }
      else {
        grantTypeList.add("authorization_code");
      }

      if (!grantTypeList.isEmpty()) {
        client.setAuthorizedGrantTypes(grantTypeList);
      }

      String authorities = clientElement.getAttribute("authorities");
      if (StringUtils.hasText(authorities)) {
        client.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList(authorities));
      }

      clients.put(clientId, client);
    }

    builder.addPropertyValue("clientDetailsStore", clients);
  }
}