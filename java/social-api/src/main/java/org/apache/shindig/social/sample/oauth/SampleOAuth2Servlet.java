package org.apache.shindig.social.sample.oauth;

import org.apache.shindig.common.servlet.HttpUtil;
import org.apache.shindig.common.servlet.InjectedServlet;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;

public class SampleOAuth2Servlet extends InjectedServlet {

  /**
   * 
   */
  private static final long serialVersionUID = -1365010221247328511L;
  
  
  @Override
  protected void doGet(HttpServletRequest servletRequest,
                       HttpServletResponse servletResponse) throws ServletException, IOException {
    HttpUtil.setNoCache(servletResponse);
    String path = servletRequest.getPathInfo();

    // dispatch
    if (path.endsWith("authorize")) {
      authorizeRequest(servletRequest, servletResponse);
    } else if (path.endsWith("accessToken")) {
      createAccessToken(servletRequest, servletResponse);
    } else {
      servletResponse.sendError(HttpServletResponse.SC_NOT_FOUND, "Unknown URL");
    }

  }


  private void createAccessToken(HttpServletRequest servletRequest,
      HttpServletResponse servletResponse) {
    
  }


  private void authorizeRequest(HttpServletRequest servletRequest,
      HttpServletResponse servletResponse) {
    
    
  }

}
