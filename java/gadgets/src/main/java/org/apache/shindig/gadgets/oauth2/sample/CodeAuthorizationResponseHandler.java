package org.apache.shindig.gadgets.oauth2.sample;

import java.io.UnsupportedEncodingException;

import javax.servlet.http.HttpServletRequest;

import org.apache.shindig.common.uri.Uri;
import org.apache.shindig.gadgets.GadgetException;
import org.apache.shindig.gadgets.http.HttpRequest;
import org.apache.shindig.gadgets.http.HttpResponse;
import org.apache.shindig.gadgets.oauth2.OAuth2Accessor;
import org.apache.shindig.gadgets.oauth2.OAuth2AuthorizationResponseHandler;
import org.apache.shindig.gadgets.oauth2.OAuth2CallbackState;
import org.apache.shindig.gadgets.oauth2.OAuth2CallbackState.State;
import org.apache.shindig.gadgets.oauth2.OAuth2Client;
import org.apache.shindig.gadgets.oauth2.OAuth2ClientAuthenticationHandler;
import org.apache.shindig.gadgets.oauth2.OAuth2Error;
import org.apache.shindig.gadgets.oauth2.OAuth2GrantTypeHandler;
import org.apache.shindig.gadgets.oauth2.OAuth2Message;
import org.apache.shindig.gadgets.oauth2.OAuth2RequestException;
import org.apache.shindig.gadgets.oauth2.OAuth2Store;
import org.apache.shindig.gadgets.oauth2.OAuth2Token;
import org.apache.shindig.gadgets.oauth2.OAuth2Utils;
import org.json.JSONException;
import org.json.JSONObject;

import com.google.inject.Inject;
import com.google.inject.Provider;

public class CodeAuthorizationResponseHandler implements OAuth2AuthorizationResponseHandler {
  private static final String[] RESPONSE_TYPES = new String[] { OAuth2Message.AUTHORIZATION_CODE };

  private final Provider<OAuth2Message> oauth2MessageProvider;
  private final OAuth2Store store;

  @Inject
  public CodeAuthorizationResponseHandler(final Provider<OAuth2Message> oauth2MessageProvider,
      final OAuth2Store store) {
    this.oauth2MessageProvider = oauth2MessageProvider;
    this.store = store;
  }

  public String[] getResponseTypes() {
    return CodeAuthorizationResponseHandler.RESPONSE_TYPES;
  }

  public OAuth2Message handleRequest(final HttpServletRequest request) {
    final OAuth2Message msg = this.oauth2MessageProvider.get();
    msg.parseRequest(request);

    OAuth2Error error = null;
    OAuth2CallbackState callbackState = null;
    final String stateString = msg.getState();

    if (stateString == null) {
      error = OAuth2Error.NO_STATE;
    } else {
      final Integer stateKey = Integer.decode(stateString);
      callbackState = this.store.getOAuth2CallbackState(stateKey);
      if (callbackState == null) {
        error = OAuth2Error.INVALID_STATE;
      } else {
        error = msg.getError();
      }
    }

    if (msg.getAuthorization() != null) {
      if (callbackState.getState() == State.AUTHORIZATION_REQUESTED) {
        callbackState.changeState(State.AUTHORIZATION_SUCCEEDED);
        try {
          error = this.setAuthorizationCode(msg.getAuthorization(), callbackState);
        } catch (final OAuth2RequestException e) {
          error = OAuth2Error.UNKNOWN_PROBLEM;
        }
      }
    } else {
      error = OAuth2Error.UNKNOWN_PROBLEM;
    }

    if (error == null) {
      return msg;
    }

    return null;
  }

  public OAuth2Error setAuthorizationCode(final String authorizationCode,
      final OAuth2CallbackState callbackState) throws OAuth2RequestException {

    final OAuth2Accessor accessor = callbackState.getAccessor();

    final String tokenUrl = this.getCompleteTokenUrl(accessor.getTokenUrl());

    HttpResponse response = null;
    final HttpRequest request = new HttpRequest(Uri.parse(tokenUrl));
    request.setMethod("POST");
    request.setHeader("Content-Type", "application/x-www-form-urlencoded; charset=utf-8");

    final String clientId = accessor.getClient().getKey();
    final String secret = accessor.getClient().getSecret();

    request.setHeader(OAuth2Message.CLIENT_ID, clientId);
    request.setHeader(OAuth2Message.CLIENT_SECRET, secret);
    request.setParam(OAuth2Message.CLIENT_ID, clientId);
    request.setParam(OAuth2Message.CLIENT_SECRET, secret);

    for (final OAuth2ClientAuthenticationHandler authenticationHandler : callbackState
        .getAuthenticationHandlers()) {
      if (authenticationHandler.geClientAuthenticationType().equalsIgnoreCase(
          accessor.getProvider().getClientAuthenticationType())) {
        authenticationHandler.addOAuth2Authentication(request, accessor);
      }
    }

    try {
      byte[] body = {};
      for (final OAuth2GrantTypeHandler grantTypeHandler : callbackState.getGrantTypeHandlers()) {
        if (grantTypeHandler.getGrantType().equalsIgnoreCase(accessor.getGrantType())) {
          body = grantTypeHandler.getAuthorizationBody(accessor, authorizationCode).getBytes(
              "UTF-8");
          break;
        }
      }

      request.setPostBody(body);

      callbackState.changeState(State.ACCESS_REQUESTED);

      response = callbackState.getFetcher().fetch(request);

      if (response == null) {
        throw new OAuth2RequestException(OAuth2Error.MISSING_SERVER_RESPONSE);
      }

      final int responseCode = response.getHttpStatusCode();
      if (responseCode != 200) {
        return CodeAuthorizationResponseHandler.parseError(response);
      }

      final String contentType = response.getHeader("Content-Type");
      final String responseString = response.getResponseAsString();
      final OAuth2Message msg = this.oauth2MessageProvider.get();
      final OAuth2Client client = callbackState.getClient();

      if (contentType.startsWith("text/plain")) {
        // Facebook does this
        msg.parseQuery("?" + responseString);
      } else if (contentType.startsWith("application/json")) {
        // Google does this
        final JSONObject responseJson = new JSONObject(responseString);
        msg.parseJSON(responseJson.toString());
      } else {
        return OAuth2Error.UNKNOWN_PROBLEM;
      }

      final OAuth2Error error = msg.getError();
      if (error == null) {
        final String accessToken = msg.getAccessToken();
        final String refreshToken = msg.getRefreshToken();
        final String expiresIn = msg.getExpiresIn();
        final String tokenType = msg.getTokenType();
        final String providerName = client.getProviderName();
        final String gadgetUri = client.getGadgetUri();
        final String scope = accessor.getScope();
        final String user = accessor.getSecurityToken().getViewerId();

        final OAuth2Store store = accessor.getStore();

        if (accessToken != null) {
          final OAuth2Token storedAccessToken = store.createToken();
          if (expiresIn != null) {
            storedAccessToken.setExpiresIn(Integer.decode(expiresIn));
          } else {
            storedAccessToken.setExpiresIn(0);
          }
          storedAccessToken.setGadgetUri(gadgetUri);
          storedAccessToken.setProviderName(providerName);
          storedAccessToken.setScope(scope);
          storedAccessToken.setSecret(accessToken);
          storedAccessToken.setTokenType(tokenType);
          storedAccessToken.setType(OAuth2Token.Type.ACCESS);
          storedAccessToken.setUser(user);
          store.setToken(storedAccessToken);
        }

        if (refreshToken != null) {
          final OAuth2Token storedRefreshToken = store.createToken();
          storedRefreshToken.setExpiresIn(0);
          storedRefreshToken.setGadgetUri(gadgetUri);
          storedRefreshToken.setProviderName(providerName);
          storedRefreshToken.setScope(scope);
          storedRefreshToken.setSecret(refreshToken);
          storedRefreshToken.setTokenType(tokenType);
          storedRefreshToken.setType(OAuth2Token.Type.REFRESH);
          storedRefreshToken.setUser(user);
          store.setToken(storedRefreshToken);
        }

        callbackState.changeState(State.ACCESS_SUCCEEDED);
      } else {
        throw new RuntimeException("@@@ TODO ARC, implement access token error handling");
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

  private String getCompleteTokenUrl(final String accessTokenUrl) throws OAuth2RequestException {
    final String ret = OAuth2Utils.buildUrl(accessTokenUrl, null, null);

    return ret;
  }

  private static OAuth2Error parseError(final HttpResponse response) {
    return OAuth2Error.UNKNOWN_PROBLEM; // TODO ARC, improve error response
  }
}
