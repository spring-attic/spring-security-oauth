package org.springframework.security.oauth.config;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.PropertyValue;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedMap;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.http.HttpSecurityBeanDefinitionParser;
import org.springframework.security.config.http.MatcherType;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Common place for OAuth namespace configuration utils.
 *
 * @author Ryan Heaton
 */
public class ConfigUtils {
  private ConfigUtils() {
  }

  public static BeanDefinition createSecurityMetadataSource(Element element, ParserContext pc) {
    List<Element> filterPatterns = DomUtils.getChildElementsByTagName(element, "url");

    if (filterPatterns.isEmpty()) {
      return null;
    }

    String patternType = element.getAttribute("path-type");
    if (!StringUtils.hasText(patternType)) {
      patternType = "ant";
    }

    MatcherType matcherType = MatcherType.valueOf(patternType);

    ManagedMap<BeanDefinition, BeanDefinition> invocationDefinitionMap = new ManagedMap<BeanDefinition, BeanDefinition>();

    for (Element filterPattern : filterPatterns) {
      String path = filterPattern.getAttribute("pattern");
      if (!StringUtils.hasText(path)) {
        pc.getReaderContext().error("pattern attribute cannot be empty or null", filterPattern);
      }

      String method = filterPattern.getAttribute("httpMethod");
      if (!StringUtils.hasText(method)) {
        method = null;
      }

      String access = filterPattern.getAttribute("resources");

      if (StringUtils.hasText(access)) {
        BeanDefinition matcher = matcherType.createMatcher(path, method);
        if (access.equals("none")) {
          invocationDefinitionMap.put(matcher, BeanDefinitionBuilder.rootBeanDefinition(Collections.class).setFactoryMethod("emptyList").getBeanDefinition());
        }
        else {
          BeanDefinitionBuilder attributeBuilder = BeanDefinitionBuilder.rootBeanDefinition(SecurityConfig.class);
          attributeBuilder.addConstructorArgValue(access);
          attributeBuilder.setFactoryMethod("createListFromCommaDelimitedString");

          if (invocationDefinitionMap.containsKey(matcher)) {
            pc.getReaderContext().warning("Duplicate URL defined: " + path
                                            + ". The original attribute values will be overwritten", pc.extractSource(filterPattern));
          }

          invocationDefinitionMap.put(matcher, attributeBuilder.getBeanDefinition());
        }
      }
    }

    BeanDefinitionBuilder fidsBuilder = BeanDefinitionBuilder.rootBeanDefinition(DefaultFilterInvocationSecurityMetadataSource.class);
    fidsBuilder.addConstructorArgValue(invocationDefinitionMap);
    fidsBuilder.getRawBeanDefinition().setSource(pc.extractSource(element));

    return fidsBuilder.getBeanDefinition();
  }

  public static List<BeanMetadataElement> findFilterChain(ParserContext parserContext, String explicitRef) {
    String filterChainRef = explicitRef;
    if (!StringUtils.hasText(filterChainRef)) {
      filterChainRef = findDefaultFilterChainBeanId(parserContext);
    }
    if (!StringUtils.hasText(filterChainRef)) {
      throw new IllegalStateException("Unable to find a filter chain to which we can add the OAuth filters. Please specify the name of one to use with the 'filter-chain-ref' attribute.");
    }
    List<BeanMetadataElement> filterChain = null;
    PropertyValue sourceList = parserContext.getRegistry().getBeanDefinition(filterChainRef).getPropertyValues().getPropertyValue("sourceList");
    if (sourceList != null && sourceList.getValue() instanceof List) {
      filterChain = (List<BeanMetadataElement>) sourceList.getValue();
    }
    if (filterChain == null) {
      throw new IllegalStateException("Unable to find the filter chain for bean id '" + filterChainRef + "'. Perhaps that bean isn't a filter chain?");
    }
    return filterChain;
  }

  protected static String findDefaultFilterChainBeanId(ParserContext parserContext) {
    BeanDefinition filterChainProxy = parserContext.getRegistry().getBeanDefinition(BeanIds.FILTER_CHAIN_PROXY);
    Map filterChainMap = (Map) filterChainProxy.getPropertyValues().getPropertyValue("filterChainMap").getValue();
    Iterator valuesIt = filterChainMap.values().iterator();
    while (valuesIt.hasNext()) {
      RuntimeBeanReference filterChainReference = (RuntimeBeanReference) valuesIt.next();
      if (!valuesIt.hasNext()) {
        return filterChainReference.getBeanName();
      }
    }

    return null;
  }

}
