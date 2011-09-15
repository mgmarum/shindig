package org.apache.shindig.gadgets.oauth2.sample;

import org.apache.shindig.gadgets.oauth2.OAuth2Accessor;
import org.apache.shindig.gadgets.oauth2.OAuth2GrantTypeHandler;
import org.apache.shindig.gadgets.oauth2.OAuth2Message;
import org.apache.shindig.gadgets.oauth2.OAuth2RequestException;

import com.google.inject.Inject;

public class ClientCredentialsGrantTypeHandler implements OAuth2GrantTypeHandler {

  @Inject
  public ClientCredentialsGrantTypeHandler() {
  }

  public String getGrantType() {
    return OAuth2Message.CLIENT_CREDENTIALS;
  }

  public String getResponseType() {
    return OAuth2Message.TOKEN_RESPONSE;
  }

  public String getAuthorizationBody(final OAuth2Accessor accessor, final String authorizationCode)
      throws OAuth2RequestException {
    return "";
  }

  public String getCompleteAuthorizationUrl(final OAuth2Accessor accessor,
      final String authorizationUrl) throws OAuth2RequestException {
    return authorizationUrl;
  }
}