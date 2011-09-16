package org.apache.shindig.gadgets.oauth2.handler.sample;

import org.apache.commons.codec.binary.Base64;
import org.apache.shindig.gadgets.http.HttpRequest;
import org.apache.shindig.gadgets.oauth2.OAuth2Accessor;
import org.apache.shindig.gadgets.oauth2.OAuth2Message;
import org.apache.shindig.gadgets.oauth2.handler.ClientAuthenticationHandler;

public class BasicAuthenticationHandler implements ClientAuthenticationHandler {
  public BasicAuthenticationHandler() {
  }

  public String geClientAuthenticationType() {
    return OAuth2Message.BASIC_AUTH_TYPE;
  }

  public void addOAuth2Authentication(final HttpRequest request, final OAuth2Accessor accessor) {
    final String clientId = accessor.getClientId();
    final String secret = accessor.getClientSecret();

    final String authString = clientId + ":" + secret;
    final byte[] authBytes = Base64.encodeBase64(authString.getBytes());
    request.setHeader("Auhtorization", "Basic: " + new String(authBytes));
  }
}