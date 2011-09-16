/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with this
 * work for additional information regarding copyright ownership. The ASF
 * licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.shindig.gadgets.oauth2.handler.sample;

import org.apache.commons.codec.binary.Base64;
import org.apache.shindig.gadgets.http.HttpRequest;
import org.apache.shindig.gadgets.oauth2.OAuth2Accessor;
import org.apache.shindig.gadgets.oauth2.OAuth2Message;
import org.apache.shindig.gadgets.oauth2.handler.ClientAuthenticationHandler;

public class BasicAuthenticationHandler implements ClientAuthenticationHandler {
  public BasicAuthenticationHandler() {
  }

  public String geClientAuthenticationType() {
    return OAuth2Message.BASIC_AUTH_TYPE;
  }

  public void addOAuth2Authentication(final HttpRequest request, final OAuth2Accessor accessor) {
    final String clientId = accessor.getClientId();
    final String secret = accessor.getClientSecret();

    final String authString = clientId + ":" + secret;
    final byte[] authBytes = Base64.encodeBase64(authString.getBytes());
    request.setHeader("Auhtorization", "Basic: " + new String(authBytes));
  }
}