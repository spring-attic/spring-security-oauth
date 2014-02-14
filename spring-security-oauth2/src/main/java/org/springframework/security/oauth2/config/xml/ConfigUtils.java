package org.springframework.security.oauth2.config.xml;

import java.util.Collections;
import java.util.List;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedMap;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.http.MatcherType;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

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

    // TODO : add support for lowercase-comparisons
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

  @SuppressWarnings({"unchecked"})
  public static List<BeanMetadataElement> findFilterChain(ParserContext parserContext, String explicitRef) {
    String filterChainRef = explicitRef;
    if (!StringUtils.hasText(filterChainRef)) {
      filterChainRef = findDefaultFilterChainBeanId(parserContext);
    }
    return (List<BeanMetadataElement>)
            parserContext.getRegistry().getBeanDefinition(filterChainRef).getConstructorArgumentValues().getArgumentValue(1,List.class).getValue();
  }

  @SuppressWarnings({"unchecked"})
  protected static String findDefaultFilterChainBeanId(ParserContext parserContext) {
    BeanDefinition filterChainList = parserContext.getRegistry().getBeanDefinition(BeanIds.FILTER_CHAINS);
    // Get the list of SecurityFilterChain beans
    List<BeanReference> filterChains = (List<BeanReference>)
              filterChainList.getPropertyValues().getPropertyValue("sourceList").getValue();

    return filterChains.get(filterChains.size() - 1).getBeanName();
  }

}
