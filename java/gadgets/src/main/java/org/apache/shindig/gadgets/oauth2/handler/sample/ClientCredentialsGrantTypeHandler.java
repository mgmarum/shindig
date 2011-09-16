package org.apache.shindig.gadgets.oauth2.handler.sample;

import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.shindig.common.uri.Uri;
import org.apache.shindig.gadgets.http.HttpRequest;
import org.apache.shindig.gadgets.oauth2.OAuth2Accessor;
import org.apache.shindig.gadgets.oauth2.OAuth2Error;
import org.apache.shindig.gadgets.oauth2.OAuth2Message;
import org.apache.shindig.gadgets.oauth2.OAuth2RequestException;
import org.apache.shindig.gadgets.oauth2.OAuth2Utils;
import org.apache.shindig.gadgets.oauth2.handler.ClientAuthenticationHandler;
import org.apache.shindig.gadgets.oauth2.handler.GrantRequestHandler;

import com.google.inject.Inject;

public class ClientCredentialsGrantTypeHandler implements GrantRequestHandler {

  private final List<ClientAuthenticationHandler> clientAuthenticationHandlers;

  @Inject
  public ClientCredentialsGrantTypeHandler(
      final List<ClientAuthenticationHandler> clientAuthenticationHandlers) {
    this.clientAuthenticationHandlers = clientAuthenticationHandlers;
  }

  public String getGrantType() {
    return OAuth2Message.CLIENT_CREDENTIALS;
  }

  public boolean isAuthorizationEndpointResponse() {
    return false;
  }

  public boolean isRedirectRequired() {
    return false;
  }

  public boolean isTokenEndpointResponse() {
    return true;
  }

  private String getAuthorizationBody(final OAuth2Accessor accessor, final String authorizationCode)
      throws OAuth2RequestException {
    String ret = "";

    final Map<String, String> queryParams = new HashMap<String, String>(5);
    queryParams.put(OAuth2Message.GRANT_TYPE, this.getGrantType());

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

  public String getCompleteUrl(final OAuth2Accessor accessor) throws OAuth2RequestException {
    final Map<String, String> queryParams = new HashMap<String, String>(4);
    queryParams.put(OAuth2Message.GRANT_TYPE, this.getGrantType());

    final String clientId = accessor.getClientId();
    final String secret = accessor.getClientSecret();
    queryParams.put(OAuth2Message.CLIENT_ID, clientId);
    queryParams.put(OAuth2Message.CLIENT_SECRET, secret);

    final String scope = accessor.getScope();
    if ((scope != null) && (scope.length() > 0)) {
      queryParams.put(OAuth2Message.SCOPE, scope);
    }

    final String ret = OAuth2Utils.buildUrl(accessor.getTokenUrl(), queryParams, null);

    return ret;
  }

  public HttpRequest getAuthorizationRequest(final OAuth2Accessor accessor,
      final String completeAuthorizationUrl) throws OAuth2RequestException {

    final HttpRequest request = new HttpRequest(Uri.parse(completeAuthorizationUrl));
    request.setMethod("GET");
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

    try {
      request.setPostBody(this.getAuthorizationBody(accessor, null).getBytes("UTF-8"));
    } catch (final UnsupportedEncodingException e) {
      throw new OAuth2RequestException(OAuth2Error.UNKNOWN_PROBLEM, "", e);
    }

    return request;
  }
}