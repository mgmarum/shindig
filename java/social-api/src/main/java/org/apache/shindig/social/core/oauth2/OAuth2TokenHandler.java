package org.apache.shindig.social.core.oauth2;

import org.apache.shindig.social.core.oauth2.OAuth2Types.TokenFormat;
import org.json.JSONObject;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * TODO: what does token_type = bearer|mac mean for subsequent requests?  Might have to add type to Signature, etc
 * TODO: generate refreshToken & associate with accessToken
 */
public class OAuth2TokenHandler {
  
  private OAuth2Service service;
  
  public OAuth2TokenHandler(OAuth2Service service) {
    this.service = service;
  }

  public void handle(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    try {
      OAuth2NormalizedRequest normalizedReq = new OAuth2NormalizedRequest(request);
      System.out.println("Normalized token request: ");
      System.out.println(normalizedReq.toString());
      service.authenticateClient(normalizedReq);
      service.validateRequestForAccessToken(normalizedReq);
      OAuth2Code accessToken = service.grantAccessToken(normalizedReq);
      sendAccessToken(response, accessToken);
    } catch(OAuth2Exception oae) {
      response.sendError(HttpServletResponse.SC_FORBIDDEN, oae.getLocalizedMessage()); // TODO: process error
    }
  }

  private void sendAccessToken(HttpServletResponse response, OAuth2Code accessToken)
      throws IOException {
    Map<String, String> bodyMap = new HashMap<String, String>();
    bodyMap.put("access_token", accessToken.getValue());
    bodyMap.put("token_type", TokenFormat.BEARER.toString());
    bodyMap.put("expires_in", (accessToken.getExpiration() - System.currentTimeMillis()) + "");
    //bodyMap.put("refresh_token", refreshToken.getSignature());
    bodyMap.put("scope", listToString(accessToken.getScope()));
    response.setStatus(HttpServletResponse.SC_OK);
    response.setContentType("application/json");
    PrintWriter out = response.getWriter();
    out.println(new JSONObject(bodyMap).toString());
    out.flush();
  }
  
  /**
   * Private utility to comma-delimit a list of Strings
   */
  private static String listToString(List<String> list) {
    if (list == null || list.isEmpty()) return "";
    StringBuilder sb = new StringBuilder();
    for (String item : list) {
     sb.append(item);
     sb.append(',');
    }
    sb.deleteCharAt(sb.length());
    return sb.toString();
  }
}
