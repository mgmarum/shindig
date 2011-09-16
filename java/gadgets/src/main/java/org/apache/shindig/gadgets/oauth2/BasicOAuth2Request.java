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
package org.apache.shindig.gadgets.oauth2;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.shindig.auth.SecurityToken;
import org.apache.shindig.common.logging.i18n.MessageKeys;
import org.apache.shindig.common.uri.Uri;
import org.apache.shindig.gadgets.GadgetException;
import org.apache.shindig.gadgets.http.HttpFetcher;
import org.apache.shindig.gadgets.http.HttpRequest;
import org.apache.shindig.gadgets.http.HttpResponse;
import org.apache.shindig.gadgets.http.HttpResponseBuilder;
import org.apache.shindig.gadgets.oauth2.handler.AuthorizationEndpointResponseHandler;
import org.apache.shindig.gadgets.oauth2.handler.ClientAuthenticationHandler;
import org.apache.shindig.gadgets.oauth2.handler.GrantRequestHandler;
import org.apache.shindig.gadgets.oauth2.handler.ResourceRequestHandler;
import org.apache.shindig.gadgets.oauth2.handler.TokenEndpointResponseHandler;
import org.json.JSONException;
import org.json.JSONObject;

import com.google.inject.Inject;
import com.google.inject.Provider;

/**
 * see {@link OAuth2Request}
 *
 */
public class BasicOAuth2Request implements OAuth2Request {

  // class name for logging purpose
  private static final String classname = BasicOAuth2Request.class.getName();

  private final OAuth2FetcherConfig fetcherConfig;

  private final HttpFetcher fetcher;

  private HttpRequest realRequest;

  private OAuth2ResponseParams responseParams;

  private OAuth2Accessor accessor;

  private OAuth2Store store;

  private boolean refreshTry = false;

  private final List<AuthorizationEndpointResponseHandler> authorizationEndpointResponseHandlers;

  private final List<ClientAuthenticationHandler> clientAuthenticationHandlers;

  private final List<GrantRequestHandler> grantRequestHandlers;

  private final List<ResourceRequestHandler> resourceRequestHandlers;

  private final List<TokenEndpointResponseHandler> tokenEndpointResponseHandlers;

  private final Provider<OAuth2Message> oauth2MessageProvider;

  /**
   * @param fetcherConfig
   *          configuration options for the fetcher
   * @param fetcher
   *          fetcher to use for actually making requests
   */
  @Inject
  public BasicOAuth2Request(final OAuth2FetcherConfig fetcherConfig, final HttpFetcher fetcher,
      final List<AuthorizationEndpointResponseHandler> authorizationEndpointResponseHandlers,
      final List<ClientAuthenticationHandler> clientAuthenticationHandlers,
      final List<GrantRequestHandler> grantRequestHandlers,
      final List<ResourceRequestHandler> resourceRequestHandlers,
      final List<TokenEndpointResponseHandler> tokenEndpointResponseHandlers,
      final Provider<OAuth2Message> oauth2MessageProvider) {
    this.fetcherConfig = fetcherConfig;
    this.fetcher = fetcher;
    this.authorizationEndpointResponseHandlers = authorizationEndpointResponseHandlers;
    this.clientAuthenticationHandlers = clientAuthenticationHandlers;
    this.grantRequestHandlers = grantRequestHandlers;
    this.resourceRequestHandlers = resourceRequestHandlers;
    this.tokenEndpointResponseHandlers = tokenEndpointResponseHandlers;
    this.oauth2MessageProvider = oauth2MessageProvider;
  }

  public HttpResponse fetch(final HttpRequest request) {
    return this.fetch(request, false);
  }

  public HttpResponse fetch(final HttpRequest request, final boolean refreshTry) {
    this.realRequest = request;
    this.responseParams = new OAuth2ResponseParams(request.getSecurityToken(), request);
    this.refreshTry = refreshTry;
    try {
      return this.fetchNoThrow();
    } catch (final RuntimeException e) {
      // We log here to record the request/response pairs that created the
      // failure.
      this.responseParams.logDetailedWarning(BasicOAuth2Request.classname, "fetch",
          MessageKeys.OAUTH_FETCH_UNEXPECTED_ERROR, e);
      throw e;
    } finally {
      this.store.removeOAuth2Accessor(this.accessor);
    }
  }

  private HttpResponse fetchNoThrow() {
    HttpResponseBuilder response = null;
    try {
      this.store = this.fetcherConfig.getOAuth2Store();

      final SecurityToken securityToken = this.realRequest.getSecurityToken();
      final OAuth2Arguments arguments = this.realRequest.getOAuth2Arguments();

      this.accessor = this.fetcherConfig.getTokenStore().getOAuth2Accessor(securityToken,
          arguments, this.realRequest.getGadget());

      response = this.fetchWithRetry();
    } catch (final OAuth2RequestException e) {
      // No data for us.
      if (OAuth2Error.UNAUTHENTICATED.name().equals(e.getError())) {
        this.responseParams.logDetailedInfo(BasicOAuth2Request.classname, "fetchNoThrow",
            MessageKeys.UNAUTHENTICATED_OAUTH, e);
      } else if (OAuth2Error.BAD_OAUTH_TOKEN_URL.name().equals(e.getError())) {
        this.responseParams.logDetailedInfo(BasicOAuth2Request.classname, "fetchNoThrow",
            MessageKeys.INVALID_OAUTH, e);
      } else {
        this.responseParams.logDetailedWarning(BasicOAuth2Request.classname, "fetchNoThrow",
            MessageKeys.OAUTH_FETCH_FATAL_ERROR, e);
      }
      this.responseParams.setSendTraceToClient(true);
      response = new HttpResponseBuilder().setHttpStatusCode(HttpResponse.SC_FORBIDDEN)
          .setStrictNoCache();
      this.responseParams.addToResponse(response, e);
      return response.create();
    } catch (final Exception e1) {
      e1.printStackTrace(); // TODO ARC
      this.responseParams.logDetailedWarning(BasicOAuth2Request.classname, "fetchNoThrow",
          MessageKeys.OAUTH_FETCH_FATAL_ERROR, e1);
      this.responseParams.setSendTraceToClient(true);
      response = new HttpResponseBuilder().setHttpStatusCode(HttpResponse.SC_FORBIDDEN)
          .setStrictNoCache();
      this.responseParams.addToResponse(response, new OAuth2RequestException("Generic fetch error",
          e1));
      return response.create();
    }

    // OK, got some data back, annotate it as necessary.
    if (response.getHttpStatusCode() >= 400) {
      this.responseParams.logDetailedWarning(BasicOAuth2Request.classname, "fetchNoThrow",
          MessageKeys.OAUTH_FETCH_FATAL_ERROR);

      this.responseParams.setSendTraceToClient(true);
    } else if ((this.responseParams.getAuthorizationUrl() != null)
        && this.responseParams.sawErrorResponse()) {
      this.responseParams.logDetailedWarning(BasicOAuth2Request.classname, "fetchNoThrow",
          MessageKeys.OAUTH_FETCH_ERROR_REPROMPT);
      this.responseParams.setSendTraceToClient(true);
    }

    this.responseParams.addToResponse(response, null);
    return response.create();
  }

  private HttpResponseBuilder fetchWithRetry() throws OAuth2RequestException {
    boolean retry;
    HttpResponseBuilder response = null;
    do {
      retry = false;
      response = this.attemptFetch();
    } while (retry);
    return response;
  }

  private HttpResponseBuilder attemptFetch() throws OAuth2RequestException {
    // Do we have an access token to use?
    if (BasicOAuth2Request.haveAccessToken(this.accessor) == null) {
      // We don't have an access token, we need to try and get one
      // First step see if we have a refresh token
      if (BasicOAuth2Request.haveRefreshToken(this.accessor) != null) {
        this.checkCanAuthorize();
        this.refreshToken();
      } else {
        this.checkCanAuthorize();

        GrantRequestHandler grantRequestHandlerUsed = null;
        for (final GrantRequestHandler grantRequestHandler : this.grantRequestHandlers) {
          if (grantRequestHandler.getGrantType().equalsIgnoreCase(this.accessor.getGrantType())) {
            grantRequestHandlerUsed = grantRequestHandler;
            break;
          }
        }

        final String completeAuthUrl = grantRequestHandlerUsed.getCompleteUrl(this.accessor);
        if (grantRequestHandlerUsed.isRedirectRequired()) {
          this.responseParams.setAuthorizationUrl(completeAuthUrl);
          return new HttpResponseBuilder().setHttpStatusCode(HttpResponse.SC_OK).setStrictNoCache();
        } else {
          this.authorize(grantRequestHandlerUsed, completeAuthUrl);
        }
      }
    }

    return this.fetchData();
  }

  private void checkCanAuthorize() throws OAuth2RequestException {
    String pageOwner = realRequest.getSecurityToken().getOwnerId();
    String pageViewer = realRequest.getSecurityToken().getViewerId();
   
    if (pageOwner == null || pageViewer == null) {
      throw new OAuth2RequestException(OAuth2Error.UNAUTHENTICATED);
    }
    if (!fetcherConfig.isViewerAccessTokensEnabled() && !pageOwner.equals(pageViewer)) {
      throw new OAuth2RequestException(OAuth2Error.NOT_OWNER);
    }
  }

  private void authorize(final GrantRequestHandler grantRequestHandler, final String completeAuthUrl)
      throws OAuth2RequestException {

    final HttpRequest authorizationRequest = grantRequestHandler.getAuthorizationRequest(
        this.accessor, completeAuthUrl);

    HttpResponse authorizationResponse;
    try {
      authorizationResponse = this.fetcher.fetch(authorizationRequest);
    } catch (final GadgetException e) {
      throw new OAuth2RequestException(OAuth2Error.UNKNOWN_PROBLEM, "", e);
    }

    if (grantRequestHandler.isAuthorizationEndpointResponse()) {
      for (final AuthorizationEndpointResponseHandler authorizationEndpointResponseHandler : this.authorizationEndpointResponseHandlers) {
        if (authorizationEndpointResponseHandler.handlesResponse(this.accessor,
            authorizationResponse)) {
          final OAuth2Message msg = authorizationEndpointResponseHandler.handleResponse(
              this.accessor, authorizationResponse);
          if (msg != null) {
            if (msg.getError() != null) {
              throw new OAuth2RequestException(OAuth2Error.UNKNOWN_PROBLEM);
            }
          }
        }
      }
    }

    if (grantRequestHandler.isTokenEndpointResponse()) {
      for (final TokenEndpointResponseHandler tokenEndpointResponseHandler : this.tokenEndpointResponseHandlers) {
        if (tokenEndpointResponseHandler.handlesResponse(this.accessor, authorizationResponse)) {
          final OAuth2Message msg = tokenEndpointResponseHandler.handleResponse(this.accessor,
              authorizationResponse);
          if (msg != null) {
            if (msg.getError() != null) {
              throw new OAuth2RequestException(OAuth2Error.UNKNOWN_PROBLEM);
            }
          }
        }
      }
    }
  }

  private static OAuth2Token haveAccessToken(final OAuth2Accessor accessor) {
    OAuth2Token ret = accessor.getAccessToken();
    if ((ret != null)) {
      if (!BasicOAuth2Request.validateAccessToken(ret)) {
        ret = null;
      }
    }
    return ret;
  }

  private static boolean validateAccessToken(final OAuth2Token accessToken) {
    final boolean ret = true;
    // Nothing really to validate
    return ret;
  }

  private static OAuth2Token haveRefreshToken(final OAuth2Accessor accessor) {
    OAuth2Token ret = accessor.getRefreshToken();
    if ((ret != null)) {
      if (!BasicOAuth2Request.validateRefreshToken(ret)) {
        ret = null;
      }
    }
    return ret;
  }

  private static boolean validateRefreshToken(final OAuth2Token refereshToken) {
    final boolean ret = true;
    // Nothing really to validate
    return ret;
  }

  private HttpResponseBuilder fetchData() throws OAuth2RequestException {
    HttpResponseBuilder builder = null;

    final HttpResponse response = this.fetchFromServer(this.realRequest);

    builder = new HttpResponseBuilder(response);

    return builder;
  }

  private HttpResponse fetchFromServer(final HttpRequest request) throws OAuth2RequestException {
    HttpResponse response = null;

    final OAuth2Token accessToken = this.accessor.getAccessToken();
    final OAuth2Token refreshToken = this.accessor.getRefreshToken();

    if (accessToken != null) {
      String tokenType = accessToken.getTokenType();
      if (tokenType == null) {
        tokenType = OAuth2Message.BEARER_TOKEN_TYPE;
      }

      for (final ResourceRequestHandler resourceRequestHandler : this.resourceRequestHandlers) {
        if (tokenType.equalsIgnoreCase(resourceRequestHandler.getTokenType())) {
          resourceRequestHandler.addOAuth2Params(this.accessor, request);
        }
      }
    }

    try {
      response = this.fetcher.fetch(request);
      if (response == null) {
        throw new OAuth2RequestException(OAuth2Error.MISSING_SERVER_RESPONSE);
      }

      final int responseCode = response.getHttpStatusCode();

      if (!this.refreshTry && (responseCode >= 400) && (responseCode < 500)) {
        if ((accessToken != null) && (refreshToken != null)) {
          // We need a refresh, remove the access token and try again
          this.accessor.setAccessToken(null);
          // make sure if we get a 2nd 401 we don't loop infinitely
          return this.fetch(this.realRequest, true);
        }
      }

      return response;
    } catch (final GadgetException e) {
      throw new OAuth2RequestException(OAuth2Error.MISSING_SERVER_RESPONSE, "", e);
    } finally {
      this.responseParams.addRequestTrace(request, response);
    }
  }

  public OAuth2Error refreshToken() throws OAuth2RequestException {
    final String refershTokenUrl = this.buildRefreshTokenUrl();

    HttpResponse response = null;
    final HttpRequest request = new HttpRequest(Uri.parse(refershTokenUrl));
    request.setMethod("POST");
    request.setHeader("Content-Type", "application/x-www-form-urlencoded; charset=utf-8");

    final String clientId = this.accessor.getClientId();
    final String secret = this.accessor.getClientSecret();

    request.setHeader(OAuth2Message.CLIENT_ID, clientId);
    request.setHeader(OAuth2Message.CLIENT_SECRET, secret);
    request.setParam(OAuth2Message.CLIENT_ID, clientId);
    request.setParam(OAuth2Message.CLIENT_SECRET, secret);

    for (final ClientAuthenticationHandler clientAuthenticationHandler : this.clientAuthenticationHandlers) {
      if (clientAuthenticationHandler.geClientAuthenticationType().equalsIgnoreCase(
          this.accessor.getClientAuthenticationType())) {
        clientAuthenticationHandler.addOAuth2Authentication(request, this.accessor);
      }
    }

    try {
      final byte[] body = this.getRefreshBody(this.accessor).getBytes("UTF-8");
      request.setPostBody(body);

      response = this.fetcher.fetch(request);
      if (response == null) {
        throw new OAuth2RequestException(OAuth2Error.MISSING_SERVER_RESPONSE);
      }
      final OAuth2Message msg = this.oauth2MessageProvider.get();

      final JSONObject responseJson = new JSONObject(response.getResponseAsString());
      msg.parseJSON(responseJson.toString());
      final OAuth2Error error = msg.getError();
      if (error == null) {
        final String accessToken = msg.getAccessToken();
        final String refreshToken = msg.getRefreshToken();
        final String expiresIn = msg.getExpiresIn();
        final String tokenType = msg.getTokenType();
        final String serviceName = this.accessor.getServiceName();
        final String gadgetUri = this.accessor.getGadgetUri();
        final String scope = this.accessor.getScope();
        final String user = this.accessor.getUser();

        if (accessToken != null) {
          final OAuth2Token storedAccessToken = this.store.createToken();
          if (expiresIn != null) {
            storedAccessToken.setExpiresIn(Integer.decode(expiresIn));
          } else {
            storedAccessToken.setExpiresIn(0);
          }
          storedAccessToken.setGadgetUri(gadgetUri);
          storedAccessToken.setServiceName(serviceName);
          storedAccessToken.setScope(scope);
          storedAccessToken.setSecret(accessToken);
          storedAccessToken.setTokenType(tokenType);
          storedAccessToken.setType(OAuth2Token.Type.ACCESS);
          storedAccessToken.setUser(user);
          this.store.setToken(storedAccessToken);
          this.accessor.setAccessToken(storedAccessToken);
        }

        if (refreshToken != null) {
          final OAuth2Token storedRefreshToken = this.store.createToken();
          storedRefreshToken.setExpiresIn(0);
          storedRefreshToken.setGadgetUri(gadgetUri);
          storedRefreshToken.setServiceName(serviceName);
          storedRefreshToken.setScope(scope);
          storedRefreshToken.setSecret(refreshToken);
          storedRefreshToken.setTokenType(tokenType);
          storedRefreshToken.setType(OAuth2Token.Type.REFRESH);
          storedRefreshToken.setUser(user);
          this.store.setToken(storedRefreshToken);
          this.accessor.setRefreshToken(storedRefreshToken);
        }
      } else {
        throw new RuntimeException("@@@ TODO ARC, implement refresh token error handling");
      }
      // TODO ARC make this exceptions better
    } catch (final GadgetException e) {
      throw new OAuth2RequestException(OAuth2Error.MISSING_SERVER_RESPONSE, "", e);
    } catch (final UnsupportedEncodingException e) {
      throw new OAuth2RequestException(OAuth2Error.MISSING_SERVER_RESPONSE, "", e);
    } catch (final JSONException e) {
      throw new OAuth2RequestException(OAuth2Error.MISSING_SERVER_RESPONSE, "", e);
    }

    return null;
  }

  private String buildRefreshTokenUrl() throws OAuth2RequestException {
    final String refreshUrl = this.accessor.getTokenUrl();
    if (refreshUrl == null) {
      throw new OAuth2RequestException(OAuth2Error.BAD_OAUTH_TOKEN_URL, "token");
    }

    final String completeRefershTokenUrl = this.getCompleteRefreshUrl(refreshUrl);

    return completeRefershTokenUrl;
  }

  private String getCompleteRefreshUrl(final String refreshUrl) throws OAuth2RequestException {
    final String ret = OAuth2Utils.buildUrl(refreshUrl, null, null);

    return ret;
  }

  private String getRefreshBody(final OAuth2Accessor accessor) throws OAuth2RequestException {
    String ret = "";

    final Map<String, String> queryParams = new HashMap<String, String>(5);
    queryParams.put(OAuth2Message.GRANT_TYPE, OAuth2Message.REFRESH_TOKEN);
    queryParams.put(OAuth2Message.REFRESH_TOKEN, this.accessor.getRefreshToken().getSecret());
    if ((accessor.getScope() != null) && (accessor.getScope().length() > 0)) {
      queryParams.put(OAuth2Message.SCOPE, accessor.getScope());
    }

    final String clientId = this.accessor.getClientId();
    final String secret = this.accessor.getClientSecret();
    queryParams.put(OAuth2Message.CLIENT_ID, clientId);
    queryParams.put(OAuth2Message.CLIENT_SECRET, secret);

    ret = OAuth2Utils.buildUrl(ret, queryParams, null);

    if ((ret.startsWith("?")) || (ret.startsWith("&"))) {
      ret = ret.substring(1);
    }

    return ret;
  }
}