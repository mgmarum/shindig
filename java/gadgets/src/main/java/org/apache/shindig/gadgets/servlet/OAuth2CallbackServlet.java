/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.servlet;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shindig.common.servlet.HttpUtil;
import org.apache.shindig.common.servlet.InjectedServlet;
import org.apache.shindig.gadgets.oauth2.OAuth2CallbackState;
import org.apache.shindig.gadgets.oauth2.OAuth2CallbackState.State;
import org.apache.shindig.gadgets.oauth2.OAuth2Error;
import org.apache.shindig.gadgets.oauth2.OAuth2Message;
import org.apache.shindig.gadgets.oauth2.OAuth2ResponseParams;
import org.apache.shindig.gadgets.oauth2.OAuth2Store;
import org.apache.shindig.gadgets.oauth2.OAuth2Utils;

import com.google.inject.Inject;

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

  private transient OAuth2Store store;

  @Inject
  public void setOAuth2Store(final OAuth2Store store) {
    this.store = store;
  }

  @Override
  protected void doGet(final HttpServletRequest request, final HttpServletResponse resp)
      throws IOException {

    final OAuth2Message msg = new OAuth2Message();
    msg.parse(request);
    final String stateString = msg.getState();
    System.err.println("@@@ stateString = " + stateString);
    final Integer stateKey = Integer.decode(stateString);
    System.err.println("@@@ stateKey = " + stateKey);
    final OAuth2CallbackState callbackState = this.store.getOAuth2CallbackState(stateKey);
    System.err.println("@@@ callbackState = " + callbackState);
    final OAuth2Error error = msg.getError();
    if (error != null) {
      callbackState.changeState(State.AUTHORIZATION_FAILED);

      final Map<String, String> queryParams = new HashMap<String, String>();
      queryParams.put(OAuth2ResponseParams.ERROR_CODE, error.toString());
      queryParams.put(OAuth2ResponseParams.ERROR_TEXT, msg.getErrorDescription());
      queryParams.put(OAuth2ResponseParams.ERROR_URI, msg.getErrorUri());
      final String errorUri = OAuth2Utils.buildUrl(callbackState.getErrorCallback(), queryParams,
          null);
      HttpUtil.setCachingHeaders(resp, OAuth2CallbackServlet.ONE_HOUR_IN_SECONDS, true);
      resp.sendRedirect(errorUri);
      return;
    }

    callbackState.changeState(State.AUTHORIZATION_SUCCEEDED);

    final StringBuilder sb = new StringBuilder();
    sb.append("<html><head></head><body>");
    sb.append("Authorization: ").append(msg.getAuthorization()).append("<p>");
    sb.append("Parameters:<p>");
    for (final String key : msg.getParameters().keySet()) {
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
    // HttpUtil.setCachingHeaders(resp, ONE_HOUR_IN_SECONDS, true);
    // resp.setContentType("text/html; charset=UTF-8");
    // resp.getWriter().write(OAuth2CallbackServlet.RESP_BODY);
  }
}
