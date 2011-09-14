package org.apache.shindig.gadgets.oauth2.sample;

import java.util.HashMap;
import java.util.Map;

import org.apache.shindig.gadgets.oauth2.OAuth2Accessor;
import org.apache.shindig.gadgets.oauth2.OAuth2GrantTypeHandler;
import org.apache.shindig.gadgets.oauth2.OAuth2Message;
import org.apache.shindig.gadgets.oauth2.OAuth2RequestException;
import org.apache.shindig.gadgets.oauth2.OAuth2Utils;

import com.google.inject.Inject;

public class CodeGrantTypeHandler implements OAuth2GrantTypeHandler {

  @Inject
  public CodeGrantTypeHandler() {
  }

  public String getGrantType() {
    return OAuth2Message.AUTHORIZATION;
  }
  
  public String getResponseType() {
    return OAuth2Message.AUTHORIZATION;
  }
  
  public String getAuthorizationBody(final OAuth2Accessor accessor, final String authorizationCode) throws OAuth2RequestException {
    String ret = "";

    final Map<String, String> queryParams = new HashMap<String, String>(5);
    queryParams.put(OAuth2Message.GRANT_TYPE, this.getGrantType());
    queryParams.put(OAuth2Message.AUTHORIZATION, authorizationCode);
    queryParams.put(OAuth2Message.REDIRECT_URI, accessor.getClient().getRedirectUri());

    final String clientId = accessor.getClient().getKey();
    final String secret = accessor.getClient().getSecret();
    queryParams.put(OAuth2Message.CLIENT_ID, clientId);
    queryParams.put(OAuth2Message.CLIENT_SECRET, secret);

    ret = OAuth2Utils.buildUrl(ret, queryParams, null);

    if ((ret.startsWith("?")) || (ret.startsWith("&"))) {
      ret = ret.substring(1);
    }

    return ret;
  }
  
  public String getCompleteAuthorizationUrl(final String authorizationUrl,
      final OAuth2Accessor accessor) throws OAuth2RequestException {
    final Map<String, String> queryParams = new HashMap<String, String>(5);
    queryParams.put(OAuth2Message.RESPONSE_TYPE, this.getResponseType());
    queryParams.put(OAuth2Message.CLIENT_ID, accessor.getClientId());
    final String redirectUri = accessor.getRedirectUri();
    if ((redirectUri != null) && (redirectUri.length() > 0)) {
      queryParams.put(OAuth2Message.REDIRECT_URI, redirectUri);
    }
    if (accessor.getCallbackState().getStateKey() != null) {
      final String state = Integer.toString(accessor.getCallbackState().getStateKey());
      if ((state != null) && (state.length() > 0)) {
        queryParams.put(OAuth2Message.STATE, state);
      }
    }
    final String scope = accessor.getScope();
    if ((scope != null) && (scope.length() > 0)) {
      queryParams.put(OAuth2Message.SCOPE, scope);
    }

    final String ret = OAuth2Utils.buildUrl(authorizationUrl, queryParams, null);

    return ret;
  }

}