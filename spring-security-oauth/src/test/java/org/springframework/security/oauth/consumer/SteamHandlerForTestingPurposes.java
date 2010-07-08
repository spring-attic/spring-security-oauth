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

package org.springframework.security.oauth.consumer;

import sun.net.www.protocol.http.Handler;

import java.net.URLConnection;
import java.net.URL;
import java.net.Proxy;
import java.io.IOException;

/**
 * @author Ryan Heaton
 */
public class SteamHandlerForTestingPurposes extends Handler {

  private final HttpURLConnectionForTestingPurposes connection;

  public SteamHandlerForTestingPurposes(HttpURLConnectionForTestingPurposes connection) {
    this.connection = connection;
  }

  @Override
  protected URLConnection openConnection(URL url) throws IOException {
    return connection;
  }

  @Override
  protected URLConnection openConnection(URL url, Proxy proxy) throws IOException {
    return connection;
  }
}
