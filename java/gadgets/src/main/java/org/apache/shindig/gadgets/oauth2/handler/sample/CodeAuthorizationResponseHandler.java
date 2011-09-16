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

import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.shindig.common.uri.Uri;
import org.apache.shindig.gadgets.GadgetException;
import org.apache.shindig.gadgets.http.HttpFetcher;
import org.apache.shindig.gadgets.http.HttpRequest;
import org.apache.shindig.gadgets.http.HttpResponse;
import org.apache.shindig.gadgets.oauth2.OAuth2Accessor;
import org.apache.shindig.gadgets.oauth2.OAuth2Error;
import org.apache.shindig.gadgets.oauth2.OAuth2Message;
import org.apache.shindig.gadgets.oauth2.OAuth2Utils;
import org.apache.shindig.gadgets.oauth2.handler.AuthorizationEndpointResponseHandler;
import org.apache.shindig.gadgets.oauth2.handler.ClientAuthenticationHandler;
import org.apache.shindig.gadgets.oauth2.handler.TokenEndpointResponseHandler;

import com.google.inject.Inject;
import com.google.inject.Provider;

/**
 * 
 * See {@link AuthorizationEndpointResponseHandler}
 * 
 * Handles the "code" flow
 */
public class CodeAuthorizationResponseHandler implements AuthorizationEndpointResponseHandler {
  private final Provider<OAuth2Message> oauth2MessageProvider;
  private final List<ClientAuthenticationHandler> clientAuthenticationHandlers;
  private final List<TokenEndpointResponseHandler> tokenEndpointResponseHandlers;
  private final HttpFetcher fetcher;

  @Inject
  public CodeAuthorizationResponseHandler(final Provider<OAuth2Message> oauth2MessageProvider,
      final List<ClientAuthenticationHandler> clientAuthenticationHandlers,
      final List<TokenEndpointResponseHandler> tokenEndpointResponseHandlers,
      final HttpFetcher fetcher) {
    this.oauth2MessageProvider = oauth2MessageProvider;
    this.clientAuthenticationHandlers = clientAuthenticationHandlers;
    this.tokenEndpointResponseHandlers = tokenEndpointResponseHandlers;
    this.fetcher = fetcher;
  }

  public OAuth2Message handleRequest(final OAuth2Accessor accessor, final HttpServletRequest request) {
    final OAuth2Message msg = this.oauth2MessageProvider.get();
    msg.parseRequest(request);

    final OAuth2Error error = this.setAuthorizationCode(msg.getAuthorization(), accessor);

    if (error == null) {
      return msg;
    }

    return null;
  }

  private String getAuthorizationBody(final OAuth2Accessor accessor, final String authorizationCode) {
    String ret = "";

    final Map<String, String> queryParams = new HashMap<String, String>(5);
    queryParams.put(OAuth2Message.GRANT_TYPE, OAuth2Message.AUTHORIZATION_CODE);
    if (authorizationCode != null) {
      queryParams.put(OAuth2Message.AUTHORIZATION, authorizationCode);
    }
    queryParams.put(OAuth2Message.REDIRECT_URI, accessor.getRedirectUri());

    final String clientId = accessor.getClientId();
    final String secret = accessor.getClientSecret();
    queryParams.put(OAuth2Message.CLIENT_ID, clientId);
    queryParams.put(OAuth2Message.CLIENT_SECRET, secret);

    ret = OAuth2Utils.buildUrl(ret, queryParams, null);

    if ((ret.startsWith("?")) || (ret.startsWith("&"))) {
      ret = ret.substring(1);
    }

    return ret;
  }

  private OAuth2Error setAuthorizationCode(final String authorizationCode,
      final OAuth2Accessor accessor) {

    final String tokenUrl = this.getCompleteTokenUrl(accessor.getTokenUrl());

    final HttpRequest request = new HttpRequest(Uri.parse(tokenUrl));
    request.setMethod("POST");
    request.setHeader("Content-Type", "application/x-www-form-urlencoded; charset=utf-8");

    final String clientId = accessor.getClientId();
    final String secret = accessor.getClientSecret();

    request.setHeader(OAuth2Message.CLIENT_ID, clientId);
    request.setHeader(OAuth2Message.CLIENT_SECRET, secret);
    request.setParam(OAuth2Message.CLIENT_ID, clientId);
    request.setParam(OAuth2Message.CLIENT_SECRET, secret);

    for (final ClientAuthenticationHandler clientAuthenticationHandler : this.clientAuthenticationHandlers) {
      if (clientAuthenticationHandler.geClientAuthenticationType().equalsIgnoreCase(
          accessor.getClientAuthenticationType())) {
        clientAuthenticationHandler.addOAuth2Authentication(request, accessor);
      }
    }

    byte[] body = {};
    try {
      body = this.getAuthorizationBody(accessor, authorizationCode).getBytes("UTF-8");
    } catch (final UnsupportedEncodingException e) {
      return OAuth2Error.UNKNOWN_PROBLEM;
    }

    request.setPostBody(body);

    HttpResponse response = null;
    try {
      response = this.fetcher.fetch(request);
    } catch (final GadgetException e) {
      return OAuth2Error.UNKNOWN_PROBLEM;
    }

    OAuth2Message msg = null;
    for (final TokenEndpointResponseHandler tokenEndpointResponseHandler : this.tokenEndpointResponseHandlers) {
      if (tokenEndpointResponseHandler.handlesResponse(accessor, response)) {
        msg = tokenEndpointResponseHandler.handleResponse(accessor, response);
        if (msg != null) {
          if (msg.getError() != null) {
            return OAuth2Error.UNKNOWN_PROBLEM;
          }
        }
      }
    }

    if (msg != null) {
      return msg.getError();
    }

    return null;
  }

  private String getCompleteTokenUrl(final String accessTokenUrl) {
    final String ret = OAuth2Utils.buildUrl(accessTokenUrl, null, null);

    return ret;
  }

  public boolean handlesRequest(final OAuth2Accessor accessor, final HttpServletRequest request) {
    if ((accessor != null) && (request != null)) {
      if (accessor.getGrantType().equalsIgnoreCase(OAuth2Message.AUTHORIZATION)) {
        return true;
      }
    }
    return false;
  }

  public boolean handlesResponse(final OAuth2Accessor accessor, final HttpResponse response) {
    return false;
  }

  public OAuth2Message handleResponse(final OAuth2Accessor accessor, final HttpResponse response) {
    return null;
  }
}
