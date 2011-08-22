package org.apache.shindig.social.core.oauth2;

import java.io.IOException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shindig.common.servlet.HttpUtil;
import org.apache.shindig.common.servlet.InjectedServlet;

import com.google.inject.Inject;

/**
 * Main servlet to catch OAuth 2.0 requests.
 */
public class OAuth2Servlet extends InjectedServlet {

  private static final long serialVersionUID = -4257719224664564922L;
  private static OAuth2AuthorizationHandler authorizationHandler;
  private static OAuth2TokenHandler tokenHandler;
  
  @Inject
  public void setOAuth2Service(OAuth2Service oauthService) {
    authorizationHandler = new OAuth2AuthorizationHandler(oauthService);
    tokenHandler = new OAuth2TokenHandler(oauthService);
  }
  
  @Override
  public void init(ServletConfig config) throws ServletException {
    super.init(config);
  }
  
  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    System.out.println("OAuth2Servlet.doGet()");
    HttpUtil.setNoCache(response);
    String path = request.getPathInfo();
    if (path.endsWith("authorize")) {
      authorizationHandler.handle(request, response);
    } else if (path.endsWith("token")) {
      tokenHandler.handle(request, response);
    } else {
      response.sendError(HttpServletResponse.SC_NOT_FOUND, "Unknown URL");
    }
  }
  
  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    doGet(request, response);
  }
}
