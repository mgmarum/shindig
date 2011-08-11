package org.apache.shindig.social.core.oauth2;

import javax.servlet.http.HttpServletRequest;

public class OAuth2Utils {
  
  public static String fetchBearerTokenFromHttpRequest(HttpServletRequest req){
    String bearerToken = req.getParameter("access_token");
    if(bearerToken == null || bearerToken.equals("")){
      String header = req.getHeader("Authorization");
      if(header != null && header.contains("Bearer")){
        String[] parts = header.split(" \t\r\n");
        bearerToken = parts[parts.length-1];
      }
    }
    return bearerToken;
  }

}
