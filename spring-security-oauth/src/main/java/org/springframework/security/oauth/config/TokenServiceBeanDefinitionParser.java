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
import org.springframework.security.oauth.provider.token.InMemoryProviderTokenServices;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * @author Ryan Heaton
 */
public class TokenServiceBeanDefinitionParser extends AbstractSingleBeanDefinitionParser {

  @Override
  protected Class getBeanClass(Element element) {
    return InMemoryProviderTokenServices.class;
  }

  @Override
  protected void doParse(Element element, ParserContext parserContext, BeanDefinitionBuilder builder) {
    String cleanup = element.getAttribute("cleanupInterval");
    if (StringUtils.hasText(cleanup)) {
      try {
        builder.addPropertyValue("cleanupIntervalSeconds", Integer.parseInt(cleanup));
      }
      catch (NumberFormatException e) {
        parserContext.getReaderContext().error("Invalid value " + cleanup + " for attribute cleanupIntervalSeconds.", element);
      }
    }
  }
}