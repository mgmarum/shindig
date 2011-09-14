package org.apache.shindig.gadgets.oauth2.sample;

import javax.servlet.http.HttpServletRequest;

import org.apache.shindig.gadgets.oauth2.OAuth2AuthorizationResponseHandler;
import org.apache.shindig.gadgets.oauth2.OAuth2Message;

public class CodeAuthorizationResponseHandler implements OAuth2AuthorizationResponseHandler {
  public String getResponseType() {
    return OAuth2Message.AUTHORIZATION;
  }

  public String[] getResponseTypes() {
    // TODO Auto-generated method stub
    return null;
  }

  public OAuth2Message handleRequest(HttpServletRequest request) {
    // TODO Auto-generated method stub
    return null;
  }
  
//  public OAuth2Error setAuthorizationCode(final String authorizationCode)
//      throws OAuth2RequestException {
//    this.authorizationCode = authorizationCode;
//    final String accessTokenUrl = this.buildAccessTokenUrl();
//    HttpResponse response = null;
//    final HttpRequest request = new HttpRequest(Uri.parse(accessTokenUrl));
//    request.setMethod("POST");
//    request.setHeader("Content-Type", "application/x-www-form-urlencoded; charset=utf-8");
//
//    final String clientId = this.client.getKey();
//    final String secret = this.client.getSecret();
//
//    request.setHeader(OAuth2Message.CLIENT_ID, clientId);
//    request.setHeader(OAuth2Message.CLIENT_SECRET, secret);
//    request.setParam(OAuth2Message.CLIENT_ID, clientId);
//    request.setParam(OAuth2Message.CLIENT_SECRET, secret);
//
//    for (final OAuth2ClientAuthenticationHandler authenticationHandler : this.authenticationHandlers) {
//      if (authenticationHandler.geClientAuthenticationType().equalsIgnoreCase(
//          this.accessor.getProvider().getClientAuthenticationType())) {
//        authenticationHandler.addOAuth2Authentication(request, this.accessor);
//      }
//    }
//
//    try {
//      String body = "";
//      for (final OAuth2GrantTypeHandler grantTypeHandler : this.grantTypeHandlers) {
//        body = grantTypeHandler.getAuthorizationBody(this.accessor, this.getAuthorizationCode());
//      }
//      
//      request.setPostBody(body.getBytes("UTF-8"));
//
//      this.changeState(State.ACCESS_REQUESTED);
//
//      response = this.fetcher.fetch(request);
//      if (response == null) {
//        throw new OAuth2RequestException(OAuth2Error.MISSING_SERVER_RESPONSE);
//      }
//
//      final int responseCode = response.getHttpStatusCode();
//      if (responseCode != 200) {
//        return OAuth2CallbackState.parseError(response);
//      }
//
//      final String contentType = response.getHeader("Content-Type");
//      final String responseString = response.getResponseAsString();
//      final OAuth2Message msg = this.oauth2MessageProvider.get();
//
//      if (contentType.startsWith("text/plain")) {
//        // Facebook does this
//        msg.parseQuery("?" + responseString);
//      } else if (contentType.startsWith("application/json")) {
//        // Google does this
//        final JSONObject responseJson = new JSONObject(responseString);
//        msg.parseJSON(responseJson.toString());
//      } else {
//        return OAuth2Error.UNKNOWN_PROBLEM;
//      }
//
//      final OAuth2Error error = msg.getError();
//      if (error == null) {
//        final String accessToken = msg.getAccessToken();
//        final String refreshToken = msg.getRefreshToken();
//        final String expiresIn = msg.getExpiresIn();
//        final String tokenType = msg.getTokenType();
//        final String providerName = this.client.getProviderName();
//        final String gadgetUri = this.client.getGadgetUri();
//        final String scope = this.accessor.getScope();
//        final String user = this.securityToken.getViewerId();
//
//        final OAuth2Store store = this.accessor.getStore();
//
//        if (accessToken != null) {
//          final OAuth2Token storedAccessToken = store.createToken();
//          if (expiresIn != null) {
//            storedAccessToken.setExpiresIn(Integer.decode(expiresIn));
//          } else {
//            storedAccessToken.setExpiresIn(0);
//          }
//          storedAccessToken.setGadgetUri(gadgetUri);
//          storedAccessToken.setProviderName(providerName);
//          storedAccessToken.setScope(scope);
//          storedAccessToken.setSecret(accessToken);
//          storedAccessToken.setTokenType(tokenType);
//          storedAccessToken.setType(OAuth2Token.Type.ACCESS);
//          storedAccessToken.setUser(user);
//          store.setToken(storedAccessToken);
//        }
//
//        if (refreshToken != null) {
//          final OAuth2Token storedRefreshToken = store.createToken();
//          storedRefreshToken.setExpiresIn(0);
//          storedRefreshToken.setGadgetUri(gadgetUri);
//          storedRefreshToken.setProviderName(providerName);
//          storedRefreshToken.setScope(scope);
//          storedRefreshToken.setSecret(refreshToken);
//          storedRefreshToken.setTokenType(tokenType);
//          storedRefreshToken.setType(OAuth2Token.Type.REFRESH);
//          storedRefreshToken.setUser(user);
//          store.setToken(storedRefreshToken);
//        }
//
//        this.changeState(State.ACCESS_SUCCEEDED);
//      } else {
//        throw new RuntimeException("@@@ TODO ARC, implement access token error handling");
//      }
//      // TODO ARC make this exceptions better
//    } catch (final GadgetException e) {
//      throw new OAuth2RequestException(OAuth2Error.MISSING_SERVER_RESPONSE, "", e);
//    } catch (final UnsupportedEncodingException e) {
//      throw new OAuth2RequestException(OAuth2Error.MISSING_SERVER_RESPONSE, "", e);
//    } catch (final JSONException e) {
//      throw new OAuth2RequestException(OAuth2Error.MISSING_SERVER_RESPONSE, "", e);
//    }
//
//    return null;
//  }

}
