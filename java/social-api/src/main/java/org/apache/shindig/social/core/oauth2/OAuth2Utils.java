package org.apache.shindig.social.core.oauth2;

import org.json.JSONException;
import org.json.JSONObject;

import javax.servlet.http.HttpServletResponse;

import java.io.IOException;

public class OAuth2Utils {
  
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
