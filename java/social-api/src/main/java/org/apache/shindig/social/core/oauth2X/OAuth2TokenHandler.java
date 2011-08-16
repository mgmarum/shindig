package org.apache.shindig.social.core.oauth2X;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shindig.social.core.oauth2X.OAuth2Types.GrantType;
import org.apache.shindig.social.core.oauth2X.OAuth2Types.TokenType;
import org.json.JSONObject;

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
    OAuth2NormalizedRequest normalizedReq = new OAuth2NormalizedRequest(request);
    System.out.println("Normalized token request: ");
    System.out.println(normalizedReq.toString());
    try {
      if (normalizedReq.containsKey("grant_type")) {
        switch ((GrantType) normalizedReq.get("grant_type")) {
        case AUTHORIZATION_CODE:
          // access token dance
          service.authenticateClient(normalizedReq);
          service.validateRequestForAccessToken(normalizedReq);
          OAuth2Signature accessToken = service.generateAccessToken(normalizedReq);
          service.registerAccessToken(normalizedReq.getString("client_id"), accessToken);
          //OAuth2Signature refreshToken = service.generateRefreshToken(normalizedReq);
          //service.registerRefreshToken(normalizedReq.getString("client_id"), refreshToken);
          
          // formulate response
          Map<String, String> bodyMap = new HashMap<String, String>();
          bodyMap.put("access_token", accessToken.getSignature());
          bodyMap.put("token_type", TokenType.BEARER.toString());
          bodyMap.put("expires_in", (accessToken.getExpiration() - System.currentTimeMillis()) + "");
          //bodyMap.put("refresh_token", refreshToken.getSignature());
          bodyMap.put("scope", listToString(accessToken.getScope()));
          response.setStatus(HttpServletResponse.SC_OK);
          response.setContentType("application/json");
          PrintWriter out = response.getWriter();
          out.println(new JSONObject(bodyMap).toString());
          out.close();
          break;
        default:
          // TODO: unrecognized - throw error
          break;
        }
      }
    } catch(OAuth2Exception oae) {
      // TODO: better error processing
      response.sendError(HttpServletResponse.SC_FORBIDDEN, oae.getLocalizedMessage());
    }
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
