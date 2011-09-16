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

import java.util.HashMap;
import java.util.Map;

import org.apache.shindig.gadgets.http.HttpRequest;
import org.apache.shindig.gadgets.oauth2.OAuth2Accessor;
import org.apache.shindig.gadgets.oauth2.OAuth2Message;
import org.apache.shindig.gadgets.oauth2.OAuth2RequestException;
import org.apache.shindig.gadgets.oauth2.OAuth2Utils;
import org.apache.shindig.gadgets.oauth2.handler.GrantRequestHandler;

import com.google.inject.Inject;

public class CodeGrantTypeHandler implements GrantRequestHandler {

  @Inject
  public CodeGrantTypeHandler() {
  }

  public String getGrantType() {
    return OAuth2Message.AUTHORIZATION;
  }

  public String getResponseType() {
    return OAuth2Message.AUTHORIZATION_CODE;
  }

  public boolean isAuthorizationEndpointResponse() {
    return true;
  }

  public boolean isRedirectRequired() {
    return true;
  }

  public boolean isTokenEndpointResponse() {
    return false;
  }

  public String getCompleteUrl(final OAuth2Accessor accessor) throws OAuth2RequestException {
    final Map<String, String> queryParams = new HashMap<String, String>(5);
    queryParams.put(OAuth2Message.RESPONSE_TYPE, this.getGrantType());
    queryParams.put(OAuth2Message.CLIENT_ID, accessor.getClientId());
    final String redirectUri = accessor.getRedirectUri();
    if ((redirectUri != null) && (redirectUri.length() > 0)) {
      queryParams.put(OAuth2Message.REDIRECT_URI, redirectUri);
    }

    final String state = accessor.getState();
    if ((state != null) && (state.length() > 0)) {
      queryParams.put(OAuth2Message.STATE, state);
    }

    final String scope = accessor.getScope();
    if ((scope != null) && (scope.length() > 0)) {
      queryParams.put(OAuth2Message.SCOPE, scope);
    }

    final String ret = OAuth2Utils.buildUrl(accessor.getAuthorizationUrl(), queryParams, null);

    return ret;
  }

  public HttpRequest getAuthorizationRequest(final OAuth2Accessor accessor,
      final String completeAuthorizationUrl) {
    return null;
  }
}