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

package org.springframework.security.oauth.common;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.net.URLCodec;

import java.io.UnsupportedEncodingException;
import java.util.BitSet;

/**
 * Utility for parameter encoding according to the OAuth spec.
 *
 * @author Ryan Heaton
 */
public class OAuthCodec extends URLCodec {

  protected static final BitSet SAFE_CHARACTERS = (BitSet) URLCodec.WWW_FORM_URL.clone();
  static {
    //The OAuth codec defines different safe characters than the standard URL codec.
    SAFE_CHARACTERS.clear('*');
    SAFE_CHARACTERS.clear(' ');
    SAFE_CHARACTERS.set('~');
  }

  /**
   * Private constructor (instance methods not accessible).
   */
  private OAuthCodec() {
  }

  /**
   * Encode the specified value.
   *
   * @param value The value to encode.
   * @return The encoded value.
   */
  public static String oauthEncode(String value) {
    if (value == null) {
      return "";
    }

    try {
      return new String(URLCodec.encodeUrl(SAFE_CHARACTERS, value.getBytes("UTF-8")), "US-ASCII");
    }
    catch (UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Decode the specified value.
   *
   * @param value The value to decode.
   * @return The decoded value.
   * @throws DecoderException when URLCodec fails
   */
  public static String oauthDecode(String value) throws DecoderException {
    if (value == null) {
      return "";
    }

    try {
      return new String(URLCodec.decodeUrl(value.getBytes("US-ASCII")), "UTF-8");
    }
    catch (UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }
  }

}
