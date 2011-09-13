package org.apache.shindig.gadgets.oauth2;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.shindig.common.uri.Uri;
import org.json.JSONObject;

public class OAuth2Message {
  public final static String AUTHORIZATION = "code";
  public final static String ACCESS_TOKEN = "access_token";
  public final static String TOKEN_TYPE = "token_type";
  public final static String EXPIRES_IN = "expires_in";
  public final static String REFRESH_TOKEN = "refresh_token";
  public final static String STATE = "state";
  public final static String ERROR = "error";
  public final static String ERROR_DESCRIPTION = "error_description";
  public final static String ERROR_URI = "error_uri";
  public final static String INVALID_REQUEST = "invalid_request";
  public final static String INVALID_CLIENT = "invalid_client";
  public final static String INVALID_GRANT = "invalid_client";
  public final static String UNAUTHORIZED_CLIENT = "authorized_client";
  public final static String UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type";
  public final static String ACCESS_DENIED = "access_denied";
  public final static String UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type";
  public final static String INVALID_SCOPE = "invalid_scope";
  public final static String SERVER_ERROR = "server_error";
  public final static String TEMPORARILY_UNAVAILABLE = "temporarily_unavailable";

  private final Map<String, String> params;

  public OAuth2Message() {
    this.params = new HashMap<String, String>(5);
  }

  public String getAccessToken() {
    return this.params.get(OAuth2Message.ACCESS_TOKEN);
  }

  public String getAuthorization() {
    return this.params.get(OAuth2Message.AUTHORIZATION);
  }

  public OAuth2Error getError() {
    OAuth2Error error = null;

    final String errorParam = this.params.get(OAuth2Message.ERROR);
    if (errorParam != null) {
      if (OAuth2Message.INVALID_REQUEST.equalsIgnoreCase(errorParam)) {
        error = OAuth2Error.INVALID_REQUEST;
      } else if (OAuth2Message.UNAUTHORIZED_CLIENT.equalsIgnoreCase(errorParam)) {
        error = OAuth2Error.UNAUTHORIZED_CLIENT;
      } else if (OAuth2Message.ACCESS_DENIED.equalsIgnoreCase(errorParam)) {
        error = OAuth2Error.ACCESS_DENIED;
      } else if (OAuth2Message.UNSUPPORTED_RESPONSE_TYPE.equalsIgnoreCase(errorParam)) {
        error = OAuth2Error.UNSUPPORTED_RESPONSE_TYPE;
      } else if (OAuth2Message.INVALID_SCOPE.equalsIgnoreCase(errorParam)) {
        error = OAuth2Error.INVALID_SCOPE;
      } else if (OAuth2Message.SERVER_ERROR.equalsIgnoreCase(errorParam)) {
        error = OAuth2Error.SERVER_ERROR;
      } else if (OAuth2Message.TEMPORARILY_UNAVAILABLE.equalsIgnoreCase(errorParam)) {
        error = OAuth2Error.TEMPORARILY_UNAVAILABLE;
      } else if (OAuth2Message.INVALID_CLIENT.equalsIgnoreCase(errorParam)) {
        error = OAuth2Error.INVALID_CLIENT;
      } else if (OAuth2Message.INVALID_GRANT.equalsIgnoreCase(errorParam)) {
        error = OAuth2Error.INVALID_GRANT;
      } else if (OAuth2Message.UNSUPPORTED_GRANT_TYPE.equalsIgnoreCase(errorParam)) {
        error = OAuth2Error.UNSUPPORTED_GRANT_TYPE;
      } else {
        error = OAuth2Error.UNKNOWN_PROBLEM;
      }

    }
    return error;
  }

  public String getErrorDescription() {
    return this.params.get(OAuth2Message.ERROR_DESCRIPTION);
  }

  public String getErrorUri() {
    return this.params.get(OAuth2Message.ERROR_URI);
  }

  public String getExpiresIn() {
    return this.params.get(OAuth2Message.EXPIRES_IN);
  }

  public Map<String, String> getParameters() {
    return this.params;
  }

  public String getRefreshToken() {
    return this.params.get(OAuth2Message.REFRESH_TOKEN);
  }

  public String getState() {
    return this.params.get(OAuth2Message.STATE);
  }

  public String getTokenType() {
    return this.params.get(OAuth2Message.TOKEN_TYPE);
  }

  public void parseRequest(final HttpServletRequest request) {
    @SuppressWarnings("unchecked")
    final Enumeration<String> paramNames = request.getParameterNames();
    while (paramNames.hasMoreElements()) {
      final String paramName = paramNames.nextElement();
      final String param = request.getParameter(paramName);
      this.params.put(paramName, param);
    }
  }

  public void parseJSON(final JSONObject response) {
    final String accessToken = response.optString(OAuth2Message.ACCESS_TOKEN, null);
    if (accessToken != null) {
      this.params.put(OAuth2Message.ACCESS_TOKEN, accessToken);
    }

    final String tokenType = response.optString(OAuth2Message.TOKEN_TYPE, null);
    if (tokenType != null) {
      this.params.put(OAuth2Message.TOKEN_TYPE, tokenType);
    }

    final String expiresIn = response.optString(OAuth2Message.EXPIRES_IN, null);
    if (expiresIn != null) {
      this.params.put(OAuth2Message.EXPIRES_IN, expiresIn);
    }

    final String refreshToken = response.optString(OAuth2Message.REFRESH_TOKEN, null);
    if (refreshToken != null) {
      this.params.put(OAuth2Message.REFRESH_TOKEN, refreshToken);
    }
  }

  public void parseQuery(final String query) {
    final Uri uri = Uri.parse(query);
    final Map<String, List<String>> params = uri.getQueryParameters();
    for (final String key : params.keySet()) {
      this.params.put(key, params.get(key).get(0));
    }
    if ((!this.params.containsKey(OAuth2Message.EXPIRES_IN))
        && (this.params.containsKey("expires"))) {
      // Facebook does this
      this.params.put(OAuth2Message.EXPIRES_IN, this.params.get("expires"));
    }
  }

  public void parseFragment(final String fragment) {
    final Uri uri = Uri.parse(fragment);
    final Map<String, List<String>> params = uri.getFragmentParameters();
    for (final String key : params.keySet()) {
      this.params.put(key, params.get(key).get(0));
    }
  }
}
