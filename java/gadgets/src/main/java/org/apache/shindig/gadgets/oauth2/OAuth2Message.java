package org.apache.shindig.gadgets.oauth2;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

public class OAuth2Message {
  private final static String AUTHORIZATION = "code";
  private final static String STATE = "state";

  private final Map<String, String> params;

  public OAuth2Message() {
    this.params = new HashMap<String, String>(2);
  }

  public void parse(final HttpServletRequest request) {
    final Enumeration<String> paramNames = request.getParameterNames();
    while (paramNames.hasMoreElements()) {
      final String paramName = paramNames.nextElement();
      final String param = request.getParameter(paramName);
      this.params.put(paramName, param);
    }
  }

  public void parse(final String response) {

  }

  public String getAuthorization() {
    return this.params.get(AUTHORIZATION);
  }

  public String getState() {
    return this.params.get(STATE);
  }

  public Map<String, String> getParameters() {
    return this.params;
  }

  private static boolean isErrorResponse(final HttpServletRequest request) {
    return false; // TODO ARC
  }
}
