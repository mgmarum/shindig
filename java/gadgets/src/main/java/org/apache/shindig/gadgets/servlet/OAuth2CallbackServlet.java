/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.servlet;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shindig.common.servlet.InjectedServlet;
import org.apache.shindig.gadgets.oauth2.OAuth2Message;

// NO IBM CONFIDENTIAL CODE OR INFORMATION!
public class OAuth2CallbackServlet extends InjectedServlet {
  private static final long serialVersionUID = 1L;

  private static final int ONE_HOUR_IN_SECONDS = 3600;

  // This bit of magic passes the entire callback URL into the opening gadget
  // for later use.
  // gadgets.io.makeRequest (or osapi.oauth) will then pick up the callback URL
  // to complete the
  // oauth dance.
  private static final String RESP_BODY = "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" "
      + "\"http://www.w3.org/TR/html4/loose.dtd\">\n"
      + "<html>\n"
      + "<head>\n"
      + "<title>Close this window</title>\n"
      + "</head>\n"
      + "<body>\n"
      + "<script type='text/javascript'>\n"
      + "try {\n"
      + "  window.opener.gadgets.io.oauthReceivedCallbackUrl_ = document.location.href;\n"
      + "} catch (e) {\n"
      + "}\n"
      + "window.close();\n"
      + "</script>\n"
      + "Close this window.\n"
      + "</body>\n" + "</html>\n";

  @Override
  protected void doGet(final HttpServletRequest request, final HttpServletResponse resp)
      throws IOException {

    OAuth2Message msg = new OAuth2Message();
    msg.parse(request);
    StringBuilder sb = new StringBuilder();
    sb.append("<html><head></head><body>");
    sb.append("Authorization: ").append(msg.getAuthorization()).append("<p>");
    sb.append("Parameters:<p>");
    for (String key : msg.getParameters().keySet()) {
      sb.append(key).append(" = ").append(msg.getParameters().get(key)).append("<p>");
    }
    sb.append("</body></html>");
    resp.getWriter().print(sb.toString());
    resp.flushBuffer();
    synchronized (this) {
      this.notifyAll();
    }

    // final OAuthCallbackState callbackState = new
    // OAuthCallbackState(stateCrypter,
    // request.getParameter(CALLBACK_STATE_PARAM));
    // if (callbackState.getRealCallbackUrl() != null) {
    // // Copy the query parameters from this URL over to the real URL.
    // final UriBuilder realUri =
    // UriBuilder.parse(callbackState.getRealCallbackUrl());
    // final Map<String, List<String>> params =
    // UriBuilder.splitParameters(req.getQueryString());
    // for (final Map.Entry<String, List<String>> entry : params.entrySet()) {
    // realUri.putQueryParameter(entry.getKey(), entry.getValue());
    // }
    // realUri.removeQueryParameter(CALLBACK_STATE_PARAM);
    // HttpUtil.setCachingHeaders(resp, ONE_HOUR_IN_SECONDS, true);
    // resp.sendRedirect(realUri.toString());
    // return;
    // }
//    HttpUtil.setCachingHeaders(resp, ONE_HOUR_IN_SECONDS, true);
//    resp.setContentType("text/html; charset=UTF-8");
//    resp.getWriter().write(OAuth2CallbackServlet.RESP_BODY);
  }
}
