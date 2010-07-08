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

import java.io.OutputStream;
import java.util.Map;
import java.util.TreeMap;

/**
 * @author Ryan Heaton
 */
public class ConnectionProps {

  public int responseCode;
  public String responseMessage;
  public String method;
  public Boolean doOutput;
  public Boolean connected;
  public OutputStream outputStream;
  public final Map<String,String> headerFields = new TreeMap<String, String>();

  public void reset() {
    this.responseCode = 0;
    this.responseMessage = null;
    this.method = null;
    this.doOutput = null;
    this.connected = null;
    this.outputStream = null;
    this.headerFields.clear();
  }

}
