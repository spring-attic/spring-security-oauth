package org.springframework.security.oauth.examples.tonr.impl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.springframework.security.oauth.consumer.client.OAuthRestTemplate;
import org.springframework.security.oauth.examples.tonr.GoogleService;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

/**
 * @author Ryan Heaton
 */
public class GoogleServiceImpl implements GoogleService {

  private OAuthRestTemplate googleRestTemplate;

  public List<String> getLastTenPicasaPictureURLs() {
//    byte[] bytes = getGoogleRestTemplate().getForObject(URI.create("https://picasaweb.google.com/data/feed/api/user/default"), byte[].class);
    byte[] bytes = getGoogleRestTemplate().getForObject(URI.create("https://picasaweb.google.com/data/feed/api/user/default?kind=photo&max-results=10"), byte[].class);
    InputStream photosXML = new ByteArrayInputStream(bytes);
    final List<String> photoUrls = new ArrayList<String>();
    SAXParserFactory parserFactory = SAXParserFactory.newInstance();
    parserFactory.setValidating(false);
    parserFactory.setXIncludeAware(false);
    parserFactory.setNamespaceAware(true);
    try {
      SAXParser parser = parserFactory.newSAXParser();
      parser.parse(photosXML, new DefaultHandler() {
        @Override
        public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
          if ("http://search.yahoo.com/mrss/".equals(uri)
            && "thumbnail".equalsIgnoreCase(localName)) {
            int width = 0;
            try {
              width = Integer.parseInt(attributes.getValue("width"));
              if (width > 100 && width < 200) {
                //just do the thumbnails that are between 100 and 200 px...
                photoUrls.add(attributes.getValue("url"));
              }
            }
            catch (NumberFormatException e) {
              //fall through...
            }
          }
        }
      });
      return photoUrls;
    }
    catch (ParserConfigurationException e) {
      throw new IllegalStateException(e);
    }
    catch (SAXException e) {
      throw new IllegalStateException(e);
    }
    catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

  public OAuthRestTemplate getGoogleRestTemplate() {
    return googleRestTemplate;
  }

  public void setGoogleRestTemplate(OAuthRestTemplate googleRestTemplate) {
    this.googleRestTemplate = googleRestTemplate;
  }
}
