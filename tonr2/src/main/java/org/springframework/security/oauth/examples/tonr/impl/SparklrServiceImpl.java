package org.springframework.security.oauth.examples.tonr.impl;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth.examples.tonr.SparklrException;
import org.springframework.security.oauth.examples.tonr.SparklrService;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.consumer.*;
import org.springframework.security.oauth2.consumer.token.OAuth2ClientTokenServices;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 * @author Ryan Heaton
 */
public class SparklrServiceImpl implements SparklrService {

  private String sparklrPhotoListURL;
  private String sparklrPhotoURLPattern;
  private OAuth2RestTemplate sparklrRestTemplate;
  private OAuth2ClientTokenServices tokenServices;

  public List<String> getSparklrPhotoIds() throws SparklrException {
    try {
      InputStream photosXML = new ByteArrayInputStream(getSparklrRestTemplate().getForObject(URI.create(getSparklrPhotoListURL()), byte[].class));

      final List<String> photoIds = new ArrayList<String>();
      SAXParserFactory parserFactory = SAXParserFactory.newInstance();
      parserFactory.setValidating(false);
      parserFactory.setXIncludeAware(false);
      parserFactory.setNamespaceAware(false);
      SAXParser parser = parserFactory.newSAXParser();
      parser.parse(photosXML, new DefaultHandler() {
        @Override
        public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
          if ("photo".equals(qName)) {
            photoIds.add(attributes.getValue("id"));
          }
        }
      });
      return photoIds;
    }
    catch (InvalidTokenException badToken) {
      //we've got a bad token, probably because it's expired.
      OAuth2ProtectedResourceDetails resource = getSparklrRestTemplate().getResource();
      OAuth2SecurityContext context = OAuth2SecurityContextHolder.getContext();
      if (context != null) {
        // this one is kind of a hack for this application
        // the problem is that the sparklr photos page doesn't remove the 'code=' request parameter.
        ((OAuth2SecurityContextImpl)context).setVerificationCode(null);
      }
      //clear any stored access tokens...
      getTokenServices().removeToken(SecurityContextHolder.getContext().getAuthentication(), resource);
      //go get a new access token...
      throw new OAuth2AccessTokenRequiredException(resource);
    }
    catch (IOException e) {
      throw new IllegalStateException(e);
    }
    catch (SAXException e) {
      throw new IllegalStateException(e);
    }
    catch (ParserConfigurationException e) {
      throw new IllegalStateException(e);
    }
  }

  public InputStream loadSparklrPhoto(String id) throws SparklrException {
    return new ByteArrayInputStream(getSparklrRestTemplate().getForObject(URI.create(String.format(getSparklrPhotoURLPattern(), id)), byte[].class));
  }

  public String getSparklrPhotoURLPattern() {

    return sparklrPhotoURLPattern;
  }

  public void setSparklrPhotoURLPattern(String sparklrPhotoURLPattern) {
    this.sparklrPhotoURLPattern = sparklrPhotoURLPattern;
  }

  public String getSparklrPhotoListURL() {
    return sparklrPhotoListURL;
  }

  public void setSparklrPhotoListURL(String sparklrPhotoListURL) {
    this.sparklrPhotoListURL = sparklrPhotoListURL;
  }

  public OAuth2RestTemplate getSparklrRestTemplate() {
    return sparklrRestTemplate;
  }

  public void setSparklrRestTemplate(OAuth2RestTemplate sparklrRestTemplate) {
    this.sparklrRestTemplate = sparklrRestTemplate;
  }

  public OAuth2ClientTokenServices getTokenServices() {
    return tokenServices;
  }

  public void setTokenServices(OAuth2ClientTokenServices tokenServices) {
    this.tokenServices = tokenServices;
  }
}
