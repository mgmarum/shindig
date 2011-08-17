package org.apache.shindig.social.core.oauth2;

import org.apache.commons.codec.binary.Base64;
import org.json.JSONException;
import org.json.JSONObject;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

public class OAuth2Utils {
  
  public static String fetchBearerTokenFromHttpRequest(HttpServletRequest req){
    String bearerToken = req.getParameter("access_token");
    if(bearerToken == null || bearerToken.equals("")){
      String header = req.getHeader("Authorization");
      if(header != null && header.contains("Bearer")){
        String[] parts = header.split("\\s+");
        bearerToken = parts[parts.length-1];
      }
    }
    return bearerToken;
  }
  
  public static String fetchClientSecretFromHttpRequest(String clientId, HttpServletRequest req){
    String secret = req.getParameter("client_secret");
    if(secret == null || secret.equals("")){
      String header = req.getHeader("Authorization");
      if(header != null && header.contains("Basic")){
        String[] parts = header.split(" \t\r\n");
        String temp = parts[parts.length-1];
        byte[] decodedSecret = Base64.decodeBase64(secret);
        try {
          temp = new String(decodedSecret,"UTF-8");
          parts = temp.split(":");
          if(parts != null && parts.length == 2 && parts[0] == clientId){
            secret = parts[1];
          }
        } catch (UnsupportedEncodingException e) {
          return null;
        }
      }
    }
    return secret;
  }
  
  public static void transmitBearerToken(OAuth2Token atoken, HttpServletResponse servletResponse) throws OAuth2Exception{
    servletResponse.setStatus(HttpServletResponse.SC_OK);
    servletResponse.setContentType("application/json");
    servletResponse.setCharacterEncoding("UTF-8");
    JSONObject token = new JSONObject();
    try {
      token.put("access_token", atoken.getValue());
      token.put("token_type", "bearer");
      servletResponse.getOutputStream().write(token.toString().getBytes("UTF-8"));
      servletResponse.getOutputStream().flush();
    } catch (JSONException e) {
      throw new OAuth2Exception(e);
    } catch (IOException e){
      throw new OAuth2Exception(e);
    }      
  }

}
