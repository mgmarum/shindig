package org.apache.shindig.gadgets.oauth2;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

public class OAuth2Message {
  private final static String AUTHORIZATION = "code";
  private final static String STATE = "state";
  private final static String ERROR = "error";
  private final static String ERROR_DESCRIPTION = "error_description";
  private final static String ERROR_URI = "error_uri";
  private final static String INVALID_REQUEST = "invalid_request";
  private final static String UNAUTHORIZED_CLIENT = "authorized_client";
  private final static String ACCESS_DENIED = "access_denied";
  private final static String UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type";
  private final static String INVALID_SCOPE = "invalid_scope";
  private final static String SERVER_ERROR = "server_error";
  private final static String TEMPORARILY_UNAVAILABLE = "temporarily_unavailable";

  private final Map<String, String> params;

  public OAuth2Message() {
    this.params = new HashMap<String, String>(2);
  }

  public void parse(final HttpServletRequest request) {
    @SuppressWarnings("unchecked")
    final Enumeration<String> paramNames = request.getParameterNames();
    while (paramNames.hasMoreElements()) {
      final String paramName = paramNames.nextElement();
      final String param = request.getParameter(paramName);
      this.params.put(paramName, param);
    }
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

  public String getAuthorization() {
    return this.params.get(OAuth2Message.AUTHORIZATION);
  }

  public String getState() {
    return this.params.get(OAuth2Message.STATE);
  }

  public Map<String, String> getParameters() {
    return this.params;
  }
}
