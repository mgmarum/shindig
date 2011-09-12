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
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shindig.common.servlet.HttpUtil;
import org.apache.shindig.common.servlet.InjectedServlet;
import org.apache.shindig.common.uri.UriBuilder;
import org.apache.shindig.gadgets.oauth2.OAuth2CallbackState;
import org.apache.shindig.gadgets.oauth2.OAuth2CallbackState.State;
import org.apache.shindig.gadgets.oauth2.OAuth2Error;
import org.apache.shindig.gadgets.oauth2.OAuth2Message;
import org.apache.shindig.gadgets.oauth2.OAuth2RequestException;
import org.apache.shindig.gadgets.oauth2.OAuth2ResponseParams;
import org.apache.shindig.gadgets.oauth2.OAuth2Store;

import com.google.inject.Inject;

// NO IBM CONFIDENTIAL CODE OR INFORMATION!
public class OAuth2CallbackServlet extends InjectedServlet {
  private static final long serialVersionUID = 1L;

  private static final String RESP_ERROR_BODY = "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" "
      + "\"http://www.w3.org/TR/html4/loose.dtd\">\n"
      + "<html>\n"
      + "<head>\n"
      + "<title>OAuth2 Error</title>\n"
      + "</head>\n"
      + "<body>\n"
      + "An error occured obtaining OAuth2 authorization.  See url for more details...\n"
      + "<script type='text/javascript'>\n"
      + "</script>\n"
      + "Close this window.\n"
      + "</body>\n"
      + "</html>\n";

  private transient OAuth2Store store;

  @Inject
  public void setOAuth2Store(final OAuth2Store store) {
    this.store = store;
  }

  @Override
  protected void doGet(final HttpServletRequest request, final HttpServletResponse resp)
      throws IOException {

    final OAuth2Message msg = new OAuth2Message();
    final String requestURI = request.getRequestURI();
    
    if (requestURI.indexOf("#") >= 0) {
      // Note : we won't see fragment params here.  We need an
      // Implicit Helper JSP or something to forward them as
      // query params.
      msg.parseFragment(requestURI.toString());
    } else {
      msg.parseRequest(request);
    }

    OAuth2Error error = null;
    OAuth2CallbackState callbackState = null;
    final String stateString = msg.getState();

    if (stateString == null) {
      error = OAuth2Error.NO_STATE;
    } else {
      final Integer stateKey = Integer.decode(stateString);
      callbackState = this.store.getOAuth2CallbackState(stateKey);
      if (callbackState == null) {
        error = OAuth2Error.INVALID_STATE;
      } else {
        error = msg.getError();
      }
    }

    if (error == null) {
      if (msg.getAuthorization() != null) {
        if (callbackState.getState() == State.AUTHORIZATION_REQUESTED) {
          callbackState.changeState(State.AUTHORIZATION_SUCCEEDED);
          try {
            error = callbackState.setAuthorizationCode(msg.getAuthorization());
          } catch (final OAuth2RequestException e) {
            e.printStackTrace(); // TODO ARC Remove Me
            error = OAuth2Error.UNKNOWN_PROBLEM;
            this.sendError(error, msg, callbackState, request, resp);
            return;
          }

          if (error == null) {
            if (callbackState.getRealCallbackUrl() != null) {
              // Copy the query parameters from this URL over to the real URL.
              final UriBuilder realUri = UriBuilder.parse(callbackState.getRealCallbackUrl());
              final Map<String, List<String>> params = UriBuilder.splitParameters(request
                  .getQueryString());
              for (final Map.Entry<String, List<String>> entry : params.entrySet()) {
                realUri.putQueryParameter(entry.getKey(), entry.getValue());
              }
              HttpUtil.setCachingHeaders(resp, OAuthCallbackServlet.ONE_HOUR_IN_SECONDS, true);
              resp.sendRedirect(realUri.toString());
              return;
            } else {
              HttpUtil.setCachingHeaders(resp, OAuthCallbackServlet.ONE_HOUR_IN_SECONDS, true);
              resp.setContentType("text/html; charset=UTF-8");
              resp.getWriter().write(OAuthCallbackServlet.RESP_BODY);
              return;
            }
          } else {
            error = OAuth2Error.INVALID_STATE_CHANGE;
          }
        }
      }
    }

    if (error != null) {
      this.sendError(error, msg, callbackState, request, resp);
      return;
    }

    throw new IOException(
        "Completed an OAuth2 Callback without finding a proper server response or error.");
  }

  private void sendError(final OAuth2Error error, final OAuth2Message msg,
      final OAuth2CallbackState callbackState, final HttpServletRequest request,
      final HttpServletResponse resp) throws IOException {
    if ((callbackState != null) && (callbackState.getRealErrorCallbackUrl() != null)) {
      callbackState.changeState(State.AUTHORIZATION_FAILED);

      // Copy the query parameters from this URL over to the real URL.
      final UriBuilder realUri = UriBuilder.parse(callbackState.getRealErrorCallbackUrl());
      final Map<String, List<String>> params = UriBuilder.splitParameters(request.getQueryString());
      for (final Map.Entry<String, List<String>> entry : params.entrySet()) {
        realUri.putQueryParameter(entry.getKey(), entry.getValue());
      }
      HttpUtil.setCachingHeaders(resp, OAuthCallbackServlet.ONE_HOUR_IN_SECONDS, true);
      resp.sendRedirect(realUri.toString());
      return;
    } else {
      final Map<String, String> queryParams = new HashMap<String, String>();
      queryParams.put(OAuth2ResponseParams.ERROR_CODE, error.toString());
      queryParams.put(OAuth2ResponseParams.ERROR_TEXT, msg.getErrorDescription());
      queryParams.put(OAuth2ResponseParams.ERROR_URI, msg.getErrorUri());
      HttpUtil.setCachingHeaders(resp, OAuthCallbackServlet.ONE_HOUR_IN_SECONDS, true);
      resp.setContentType("text/html; charset=UTF-8");
      resp.getWriter().write(OAuth2CallbackServlet.RESP_ERROR_BODY);
      return;
    }

  }
}