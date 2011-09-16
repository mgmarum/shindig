package org.apache.shindig.gadgets.oauth2.handler.sample;

import java.util.HashMap;
import java.util.Map;

import org.apache.shindig.common.uri.Uri;
import org.apache.shindig.gadgets.http.HttpRequest;
import org.apache.shindig.gadgets.oauth2.OAuth2Accessor;
import org.apache.shindig.gadgets.oauth2.OAuth2Error;
import org.apache.shindig.gadgets.oauth2.OAuth2Message;
import org.apache.shindig.gadgets.oauth2.OAuth2RequestException;
import org.apache.shindig.gadgets.oauth2.OAuth2Token;
import org.apache.shindig.gadgets.oauth2.OAuth2Utils;
import org.apache.shindig.gadgets.oauth2.handler.ResourceRequestHandler;

public class BearerTokenHandler implements ResourceRequestHandler {

  public BearerTokenHandler() {
  }

  public String getTokenType() {
    return OAuth2Message.BEARER_TOKEN_TYPE;
  }

  public void addOAuth2Params(final OAuth2Accessor accessor, final HttpRequest request)
      throws OAuth2RequestException {
    final Uri unAuthorizedRequestUri = request.getUri();
    if (unAuthorizedRequestUri == null) {
      throw new OAuth2RequestException(OAuth2Error.UNKNOWN_PROBLEM, "Uri is null??");
    }

    final OAuth2Token accessToken = accessor.getAccessToken();

    final Map<String, String> queryParams = new HashMap<String, String>(1);
    queryParams.put(OAuth2Message.ACCESS_TOKEN, accessToken.getSecret());
    final String authorizedUriString = OAuth2Utils.buildUrl(unAuthorizedRequestUri.toString(),
        queryParams, null);

    request.setUri(Uri.parse(authorizedUriString));

    String tokenType = "Bearer";

    if ((accessToken.getTokenType() != null) && (accessToken.getTokenType().length() > 0)) {
      tokenType = accessToken.getTokenType();
    }

    if (tokenType.equalsIgnoreCase("Bearer")) {
      request.setHeader("Authorization", "Bearer " + accessToken.getSecret());
    } else {
      throw new OAuth2RequestException(OAuth2Error.UNKNOWN_PROBLEM,
          "BearerTokenHandler can only handle Bearer tokens. " + tokenType);
    }
  }
}
