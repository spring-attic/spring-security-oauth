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

package org.springframework.security.oauth.config;

import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.oauth.common.signature.HMAC_SHA1SignatureMethod;
import org.springframework.security.oauth.common.signature.SharedConsumerSecret;
import org.springframework.security.oauth.consumer.BaseProtectedResourceDetails;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author Ryan Heaton
 */
public class ProtectedResourceDetailsBeanDefinitionParser extends AbstractSingleBeanDefinitionParser {

  @Override
  protected Class getBeanClass(Element element) {
    return ProtectedResourceDetailsServiceFactoryBean.class;
  }

  @Override
  protected void doParse(Element element, ParserContext parserContext, BeanDefinitionBuilder builder) {
    List consumerElements = DomUtils.getChildElementsByTagName(element, "resource");
    for (Object item : consumerElements) {
      BeanDefinitionBuilder resource = BeanDefinitionBuilder.rootBeanDefinition(BaseProtectedResourceDetails.class);
      Element consumerElement = (Element) item;
      String id = consumerElement.getAttribute("id");
      if (StringUtils.hasText(id)) {
        resource.addPropertyValue("id", id);
      }
      else {
        parserContext.getReaderContext().error("A resource id must be supplied with the definition of a protected resource.", consumerElement);
      }

      String key = consumerElement.getAttribute("key");
      if (StringUtils.hasText(key)) {
        resource.addPropertyValue("consumerKey", key);
      }
      else {
        parserContext.getReaderContext().error("A consumer key must be supplied with the definition of a protected resource.", consumerElement);
      }

      String secret = consumerElement.getAttribute("secret");
      if (StringUtils.hasText(secret)) {
        resource.addPropertyValue("sharedSecret", secret);
      }
      else {
        parserContext.getReaderContext().error("A shared secret must be supplied with the definition of a resource.", consumerElement);
      }

      String requestTokenURL = consumerElement.getAttribute("request-token-url");
      if (StringUtils.hasText(requestTokenURL)) {
        resource.addPropertyValue("requestTokenURL", requestTokenURL);
      }
      else {
        parserContext.getReaderContext().error("A request token URL must be supplied with the definition of a resource.", consumerElement);
      }

      String requestTokenMethod = consumerElement.getAttribute("request-token-method");
      if (StringUtils.hasText(requestTokenMethod)) {
        resource.addPropertyValue("requestTokenHttpMethod", requestTokenMethod);
      }

      String accessTokenURL = consumerElement.getAttribute("access-token-url");
      if (StringUtils.hasText(accessTokenURL)) {
        resource.addPropertyValue("accessTokenURL", accessTokenURL);
      }
      else {
        parserContext.getReaderContext().error("An access token URL must be supplied with the definition of a resource.", consumerElement);
      }

      String accessTokenMethod = consumerElement.getAttribute("access-token-method");
      if (StringUtils.hasText(accessTokenMethod)) {
        resource.addPropertyValue("accessTokenHttpMethod", accessTokenMethod);
      }

      String userAuthorizationURL = consumerElement.getAttribute("user-authorization-url");
      if (StringUtils.hasText(userAuthorizationURL)) {
        resource.addPropertyValue("userAuthorizationURL", userAuthorizationURL);
      }
      else {
        parserContext.getReaderContext().error("A user authorization URL must be supplied with the definition of a resource.", consumerElement);
      }

      String sigMethod = consumerElement.getAttribute("signature-method");
      if (!StringUtils.hasText(sigMethod)) {
        sigMethod = HMAC_SHA1SignatureMethod.SIGNATURE_NAME;
      }
      resource.addPropertyValue("signatureMethod", sigMethod);

      String acceptsHeader = consumerElement.getAttribute("accepts-authorization-header");
      if (StringUtils.hasText(acceptsHeader)) {
        resource.addPropertyValue("acceptsAuthorizationHeader", Boolean.valueOf(acceptsHeader));
      }

      String headerRealm = consumerElement.getAttribute("authorization-header-realm");
      if (StringUtils.hasText(headerRealm)) {
        resource.addPropertyValue("authorizationHeaderRealm", headerRealm);
      }

      String use10a = consumerElement.getAttribute("use10a");
      if (StringUtils.hasText(use10a)) {
        resource.addPropertyValue("use10a", "true".equals(use10a));
      }

      List additionalParameters = DomUtils.getChildElementsByTagName(consumerElement, "addtionalParameter");
      if (additionalParameters != null && !additionalParameters.isEmpty()) {
        Map<String, String> additionalParams = new HashMap<String, String>();
        for (Object additionalParameter : additionalParameters) {
          additionalParams.put(((Element)additionalParameter).getAttribute("name"), ((Element)additionalParameter).getAttribute("value"));
        }
        resource.addPropertyValue("additionalParameters", additionalParams);
      }

      List additionalRequestHeaders = DomUtils.getChildElementsByTagName(consumerElement, "additionalRequestHeader");
      if (additionalRequestHeaders != null && !additionalRequestHeaders.isEmpty()) {
        Map<String, String> headers = new HashMap<String, String>();
        for (Object additionalParameter : additionalRequestHeaders) {
          headers.put(((Element)additionalParameter).getAttribute("name"), ((Element)additionalParameter).getAttribute("value"));
        }
        resource.addPropertyValue("additionalRequestHeaders", headers);
      }

      parserContext.getRegistry().registerBeanDefinition(id, resource.getBeanDefinition());
    }
  }
}