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
import org.apache.shindig.gadgets.oauth2.OAuth2Accessor;
import org.apache.shindig.gadgets.oauth2.OAuth2AuthorizationResponseHandler;
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

  private transient List<OAuth2AuthorizationResponseHandler> authorizationResponseHandlers;
  private transient OAuth2Store store;

  @Inject
  public void setOAuth2Store(final OAuth2Store store) {
    this.store = store;
  }

  @Inject
  public void setAuthorizationResponseHandlers(
      final List<OAuth2AuthorizationResponseHandler> authorizationResponseHandlers) {
    this.authorizationResponseHandlers = authorizationResponseHandlers;
  }

  @Override
  protected void doGet(final HttpServletRequest request, final HttpServletResponse resp)
      throws IOException {

    final String requestStateKey = request.getParameter(OAuth2Message.STATE);
    final Integer index = Integer.decode(requestStateKey);

    OAuth2Accessor accessor;
    OAuth2Message msg;
    try {
      accessor = this.store.getOAuth2Accessor(index);

      msg = null;
      for (final OAuth2AuthorizationResponseHandler authorizationResponseHandler : this.authorizationResponseHandlers) {
        msg = authorizationResponseHandler.handleRequest(accessor, request);
        if (msg != null) {
          break;
        }
      }
    } catch (final OAuth2RequestException e) {
      this.sendError(OAuth2Error.UNKNOWN_PROBLEM, null, null, request, resp);
      return;
    }

    OAuth2Error error = null;
    if (msg == null) {
      this.sendError(OAuth2Error.UNKNOWN_PROBLEM, null, null, request, resp);
      return;
    }

    if (error == null) {
      error = msg.getError();
    }

    if (error == null) {
      if (accessor.getRealCallbackUrl() != null) {
        // Copy the query parameters from this URL over to the real URL.
        final UriBuilder realUri = UriBuilder.parse(accessor.getRealCallbackUrl());
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
    }

    this.sendError(error, msg, accessor, request, resp);
  }

  private void sendError(final OAuth2Error error, final OAuth2Message msg,
      final OAuth2Accessor accessor, final HttpServletRequest request,
      final HttpServletResponse resp) throws IOException {
    if ((accessor != null) && (accessor.getRealErrorCallbackUrl() != null)) {
      // Copy the query parameters from this URL over to the real URL.
      final UriBuilder realUri = UriBuilder.parse(accessor.getRealErrorCallbackUrl());
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
      if (msg != null) {
        queryParams.put(OAuth2ResponseParams.ERROR_TEXT, msg.getErrorDescription());
        queryParams.put(OAuth2ResponseParams.ERROR_URI, msg.getErrorUri());
      } else {
        queryParams.put(OAuth2ResponseParams.ERROR_TEXT, "No valid OAuth2Error reported.");
      }
      HttpUtil.setCachingHeaders(resp, OAuthCallbackServlet.ONE_HOUR_IN_SECONDS, true);
      resp.setContentType("text/html; charset=UTF-8");
      resp.getWriter().write(OAuth2CallbackServlet.RESP_ERROR_BODY);
      return;
    }
  }
}