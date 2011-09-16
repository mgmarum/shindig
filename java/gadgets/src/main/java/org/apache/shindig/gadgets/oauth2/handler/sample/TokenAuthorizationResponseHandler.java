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

import org.apache.shindig.gadgets.GadgetException;
import org.apache.shindig.gadgets.http.HttpResponse;
import org.apache.shindig.gadgets.oauth2.OAuth2Accessor;
import org.apache.shindig.gadgets.oauth2.OAuth2Error;
import org.apache.shindig.gadgets.oauth2.OAuth2Message;
import org.apache.shindig.gadgets.oauth2.OAuth2RequestException;
import org.apache.shindig.gadgets.oauth2.OAuth2Store;
import org.apache.shindig.gadgets.oauth2.OAuth2Token;
import org.apache.shindig.gadgets.oauth2.handler.TokenEndpointResponseHandler;
import org.json.JSONException;
import org.json.JSONObject;

import com.google.inject.Inject;
import com.google.inject.Provider;

public class TokenAuthorizationResponseHandler implements TokenEndpointResponseHandler {
  private final Provider<OAuth2Message> oauth2MessageProvider;
  private final OAuth2Store store;

  @Inject
  public TokenAuthorizationResponseHandler(final Provider<OAuth2Message> oauth2MessageProvider,
      final OAuth2Store store) {
    this.oauth2MessageProvider = oauth2MessageProvider;
    this.store = store;
  }

  public boolean handlesResponse(final OAuth2Accessor accessor, final HttpResponse response) {
    return true;
  }

  public OAuth2Message handleResponse(final OAuth2Accessor accessor, final HttpResponse response) {
    if (response == null) {
      return null;
    }

    final int responseCode = response.getHttpStatusCode();
    if (responseCode != 200) {
      return null;
    }

    final String contentType = response.getHeader("Content-Type");
    final String responseString = response.getResponseAsString();
    final OAuth2Message msg = this.oauth2MessageProvider.get();

    try {
      if (contentType.startsWith("text/plain")) {
        // Facebook does this
        msg.parseQuery("?" + responseString);
      } else if (contentType.startsWith("application/json")) {
        // Google does this
        final JSONObject responseJson = new JSONObject(responseString);
        msg.parseJSON(responseJson.toString());
      } else {
        return null;
      }

      final OAuth2Error error = msg.getError();
      if (error == null) {
        final String accessToken = msg.getAccessToken();
        final String refreshToken = msg.getRefreshToken();
        final String expiresIn = msg.getExpiresIn();
        final String tokenType = msg.getTokenType();
        final String providerName = accessor.getServiceName();
        final String gadgetUri = accessor.getGadgetUri();
        final String scope = accessor.getScope();
        final String user = accessor.getUser();

        if (accessToken != null) {
          final OAuth2Token storedAccessToken = this.store.createToken();
          if (expiresIn != null) {
            storedAccessToken.setExpiresIn(Integer.decode(expiresIn));
          } else {
            storedAccessToken.setExpiresIn(0);
          }
          storedAccessToken.setGadgetUri(gadgetUri);
          storedAccessToken.setServiceName(providerName);
          storedAccessToken.setScope(scope);
          storedAccessToken.setSecret(accessToken);
          storedAccessToken.setTokenType(tokenType);
          storedAccessToken.setType(OAuth2Token.Type.ACCESS);
          storedAccessToken.setUser(user);
          this.store.setToken(storedAccessToken);
          accessor.setAccessToken(storedAccessToken);
        }

        if (refreshToken != null) {
          final OAuth2Token storedRefreshToken = this.store.createToken();
          storedRefreshToken.setExpiresIn(0);
          storedRefreshToken.setGadgetUri(gadgetUri);
          storedRefreshToken.setServiceName(providerName);
          storedRefreshToken.setScope(scope);
          storedRefreshToken.setSecret(refreshToken);
          storedRefreshToken.setTokenType(tokenType);
          storedRefreshToken.setType(OAuth2Token.Type.REFRESH);
          storedRefreshToken.setUser(user);
          this.store.setToken(storedRefreshToken);
          accessor.setRefreshToken(storedRefreshToken);
        }
      } else {
        throw new RuntimeException("@@@ TODO ARC, implement access token error handling");
      }
    } catch (final NumberFormatException e) {
      return null;
    } catch (final OAuth2RequestException e) {
      return null;
    } catch (final JSONException e) {
      return null;
    } catch (final GadgetException e) {
      return null;
    }

    return msg;
  }

  private static OAuth2Error parseError(final HttpResponse response) {
    return OAuth2Error.UNKNOWN_PROBLEM; // TODO ARC, improve error response
  }

}
