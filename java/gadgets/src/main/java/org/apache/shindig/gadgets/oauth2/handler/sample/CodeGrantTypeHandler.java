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