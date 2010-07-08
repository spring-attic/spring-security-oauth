package org.springframework.security.oauth.examples.tonr.impl;

import org.springframework.security.oauth.consumer.CoreOAuthConsumerSupport;
import org.springframework.security.oauth.consumer.OAuthConsumerSupport;
import org.springframework.security.oauth.consumer.ProtectedResourceDetailsService;
import org.springframework.security.oauth.consumer.token.OAuthConsumerToken;
import org.springframework.security.oauth.examples.tonr.SparklrException;
import org.springframework.security.oauth.examples.tonr.SparklrService;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/**
 * @author Ryan Heaton
 */
public class SparklrServiceImpl implements SparklrService {

  private String sparklrPhotoListURL;
  private String sparklrPhotoURLPattern;
  private OAuthConsumerSupport support = new CoreOAuthConsumerSupport();
  private ProtectedResourceDetailsService resourceDetailsService;

  public List<String> getSparklrPhotoIds(OAuthConsumerToken accessToken) throws SparklrException {
    try {
      InputStream photosXML = getSupport().readProtectedResource(new URL(getSparklrPhotoListURL()), accessToken, "GET");

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

  public InputStream loadSparklrPhoto(String id, OAuthConsumerToken accessToken) throws SparklrException {
    try {
      return getSupport().readProtectedResource(new URL(String.format(getSparklrPhotoURLPattern(), id)), accessToken, "GET");
    }
    catch (MalformedURLException e) {
      throw new IllegalStateException(e);
    }
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

  public OAuthConsumerSupport getSupport() {
    return support;
  }

  public void setSupport(OAuthConsumerSupport support) {
    this.support = support;
  }

  public ProtectedResourceDetailsService getResourceDetailsService() {
    return resourceDetailsService;
  }

  public void setResourceDetailsService(ProtectedResourceDetailsService resourceDetailsService) {
    this.resourceDetailsService = resourceDetailsService;
  }
}
