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

package org.springframework.security.oauth.config;

import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth.common.signature.RSAKeySecret;
import org.springframework.security.oauth.common.signature.SharedConsumerSecret;
import org.springframework.security.oauth.provider.BaseConsumerDetails;
import org.springframework.security.oauth.provider.InMemoryConsumerDetailsService;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * @author Ryan Heaton
 * @author Andrew McCall
 */
public class ConsumerServiceBeanDefinitionParser extends AbstractSingleBeanDefinitionParser {

  @Override
  protected Class getBeanClass(Element element) {
    return InMemoryConsumerDetailsService.class;
  }

  @Override
  protected void doParse(Element element, ParserContext parserContext, BeanDefinitionBuilder builder) {
    List consumerElements = DomUtils.getChildElementsByTagName(element, "consumer");
    Map<String, BaseConsumerDetails> consumers = new TreeMap<String, BaseConsumerDetails>();
    for (Object item : consumerElements) {
      BaseConsumerDetails consumer = new BaseConsumerDetails();
      Element consumerElement = (Element) item;
      String key = consumerElement.getAttribute("key");
      if (StringUtils.hasText(key)) {
        consumer.setConsumerKey(key);
      }
      else {
        parserContext.getReaderContext().error("A consumer key must be supplied with the definition of a consumer.", consumerElement);
      }

      String secret = consumerElement.getAttribute("secret");
      if (secret != null) {
        String typeOfSecret = consumerElement.getAttribute("typeOfSecret");
        if ("rsa-cert".equals(typeOfSecret)) {
          try {
            Certificate cert = CertificateFactory.getInstance("X.509").generateCertificate(parserContext.getReaderContext().getResourceLoader().getResource(secret).getInputStream());
            consumer.setSignatureSecret(new RSAKeySecret(cert.getPublicKey()));
          }
          catch (IOException e) {
            parserContext.getReaderContext().error("RSA certificate not found at " + secret + ".", consumerElement, e);
          }
          catch (CertificateException e) {
            parserContext.getReaderContext().error("Invalid RSA certificate at " + secret + ".", consumerElement, e);
          }
        }
        else {
          consumer.setSignatureSecret(new SharedConsumerSecret(secret));
        }
      }
      else {
        parserContext.getReaderContext().error("A consumer secret must be supplied with the definition of a consumer.", consumerElement);
      }

      String name = consumerElement.getAttribute("name");
      if (StringUtils.hasText(name)) {
        consumer.setConsumerName(name);
      }

      String authorities = consumerElement.getAttribute("authorities");
      if (authorities != null) {
        consumer.setAuthorities(AuthorityUtils.commaSeparatedStringToAuthorityList(authorities));
      }

      String resourceName = consumerElement.getAttribute("resourceName");
      if (resourceName != null) {
        consumer.setResourceName(resourceName);
      }

      String resourceDescription = consumerElement.getAttribute("resourceDescription");
      if (resourceDescription != null) {
        consumer.setResourceDescription(resourceDescription);
      }

      String requiredToObtainAuthenticatedToken = consumerElement.getAttribute("requiredToObtainAuthenticatedToken");
      if (requiredToObtainAuthenticatedToken != null && "false".equalsIgnoreCase(requiredToObtainAuthenticatedToken)) {
        consumer.setRequiredToObtainAuthenticatedToken(false);
      }

      consumers.put(key, consumer);
    }

    builder.addPropertyValue("consumerDetailsStore", consumers);
  }
}
