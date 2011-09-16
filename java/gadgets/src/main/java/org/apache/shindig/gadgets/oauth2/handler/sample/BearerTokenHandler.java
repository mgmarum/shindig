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

import org.apache.shindig.common.uri.Uri;
import org.apache.shindig.gadgets.http.HttpRequest;
import org.apache.shindig.gadgets.oauth2.OAuth2Accessor;
import org.apache.shindig.gadgets.oauth2.OAuth2Error;
import org.apache.shindig.gadgets.oauth2.OAuth2Message;
import org.apache.shindig.gadgets.oauth2.OAuth2RequestException;
import org.apache.shindig.gadgets.oauth2.OAuth2Token;
import org.apache.shindig.gadgets.oauth2.OAuth2Utils;
import org.apache.shindig.gadgets.oauth2.handler.ResourceRequestHandler;

/**
 * 
 * See {@link ResourceRequestHandler}
 * 
 * Handles the Bearer token type
 */
public class BearerTokenHandler implements ResourceRequestHandler {

  public BearerTokenHandler() {
  }

  public String getTokenType() {
    return OAuth2Message.BEARER_TOKEN_TYPE;
  }

  public void addOAuth2Params(final OAuth2Accessor accessor, final HttpRequest request)
      throws OAuth2RequestException {
    final Uri unAuthorizedRequestUri = request.getUri();
    if (unAuthorizedRequestUri == null) {
      throw new OAuth2RequestException(OAuth2Error.UNKNOWN_PROBLEM, "Uri is null??");
    }

    final OAuth2Token accessToken = accessor.getAccessToken();

    final Map<String, String> queryParams = new HashMap<String, String>(1);
    queryParams.put(OAuth2Message.ACCESS_TOKEN, accessToken.getSecret());
    final String authorizedUriString = OAuth2Utils.buildUrl(unAuthorizedRequestUri.toString(),
        queryParams, null);

    request.setUri(Uri.parse(authorizedUriString));

    String tokenType = "Bearer";

    if ((accessToken.getTokenType() != null) && (accessToken.getTokenType().length() > 0)) {
      tokenType = accessToken.getTokenType();
    }

    if (tokenType.equalsIgnoreCase("Bearer")) {
      request.setHeader("Authorization", "Bearer " + accessToken.getSecret());
    } else {
      throw new OAuth2RequestException(OAuth2Error.UNKNOWN_PROBLEM,
          "BearerTokenHandler can only handle Bearer tokens. " + tokenType);
    }
  }
}
