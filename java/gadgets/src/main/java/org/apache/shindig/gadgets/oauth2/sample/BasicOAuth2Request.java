/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2.sample;

import java.util.HashMap;
import java.util.Map;

import org.apache.shindig.common.logging.i18n.MessageKeys;
import org.apache.shindig.common.uri.Uri;
import org.apache.shindig.gadgets.GadgetException;
import org.apache.shindig.gadgets.http.HttpFetcher;
import org.apache.shindig.gadgets.http.HttpRequest;
import org.apache.shindig.gadgets.http.HttpResponse;
import org.apache.shindig.gadgets.http.HttpResponseBuilder;
import org.apache.shindig.gadgets.oauth2.OAuth2Accessor;
import org.apache.shindig.gadgets.oauth2.OAuth2CallbackState;
import org.apache.shindig.gadgets.oauth2.OAuth2CallbackState.State;
import org.apache.shindig.gadgets.oauth2.OAuth2Error;
import org.apache.shindig.gadgets.oauth2.OAuth2FetcherConfig;
import org.apache.shindig.gadgets.oauth2.OAuth2ProtocolException;
import org.apache.shindig.gadgets.oauth2.OAuth2Request;
import org.apache.shindig.gadgets.oauth2.OAuth2RequestException;
import org.apache.shindig.gadgets.oauth2.OAuth2ResponseParams;
import org.apache.shindig.gadgets.oauth2.OAuth2Token;
import org.apache.shindig.gadgets.oauth2.OAuth2Utils;

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public class BasicOAuth2Request implements OAuth2Request {
  // class name for logging purpose
  private static final String classname = BasicOAuth2Request.class.getName();

  protected final OAuth2FetcherConfig fetcherConfig;

  private final HttpFetcher fetcher;

  private HttpRequest realRequest;

  private OAuth2ResponseParams responseParams;

  private OAuth2Accessor accessor;

  private OAuth2CallbackState callbackState;

  /**
   * @param fetcherConfig
   *          configuration options for the fetcher
   * @param fetcher
   *          fetcher to use for actually making requests
   */
  public BasicOAuth2Request(final OAuth2FetcherConfig fetcherConfig, final HttpFetcher fetcher) {
    this.fetcherConfig = fetcherConfig;
    this.fetcher = fetcher;
  }

  public HttpResponse fetch(final HttpRequest request) {
    this.realRequest = request;
    this.responseParams = new OAuth2ResponseParams(request.getSecurityToken(), request);
    try {
      return this.fetchNoThrow();
    } catch (final RuntimeException e) {
      // We log here to record the request/response pairs that created the
      // failure.
      this.responseParams.logDetailedWarning(BasicOAuth2Request.classname, "fetch",
          MessageKeys.OAUTH_FETCH_UNEXPECTED_ERROR, e);
      throw e;
    }
  }

  private HttpResponse fetchNoThrow() {
    HttpResponseBuilder response = null;
    try {
      this.accessor = this.fetcherConfig.getTokenStore().getOAuth2Accessor(
          this.realRequest.getSecurityToken(), this.realRequest.getOAuth2Arguments(),
          this.fetcherConfig, this.fetcher);
      this.callbackState = this.accessor.getCallbackState();
      response = this.fetchWithRetry();
    } catch (final OAuth2RequestException e) {
      e.printStackTrace(); // TODO ARC
      // No data for us.
      if (OAuth2Error.UNAUTHENTICATED.name().equals(e.getError())) {
        this.responseParams.logDetailedInfo(BasicOAuth2Request.classname, "fetchNoThrow",
            MessageKeys.UNAUTHENTICATED_OAUTH, e);
      } else if (OAuth2Error.BAD_OAUTH_TOKEN_URL.name().equals(e.getError())) {
        this.responseParams.logDetailedInfo(BasicOAuth2Request.classname, "fetchNoThrow",
            MessageKeys.INVALID_OAUTH, e);
      } else {
        this.responseParams.logDetailedWarning(BasicOAuth2Request.classname, "fetchNoThrow",
            MessageKeys.OAUTH_FETCH_FATAL_ERROR, e);
      }
      this.responseParams.setSendTraceToClient(true);
      response = new HttpResponseBuilder().setHttpStatusCode(HttpResponse.SC_FORBIDDEN)
          .setStrictNoCache();
      this.responseParams.addToResponse(response, e);
      return response.create();
    }

    // OK, got some data back, annotate it as necessary.
    if (response.getHttpStatusCode() >= 400) {
      this.responseParams.logDetailedWarning(BasicOAuth2Request.classname, "fetchNoThrow",
          MessageKeys.OAUTH_FETCH_FATAL_ERROR);

      this.responseParams.setSendTraceToClient(true);
    } else if ((this.responseParams.getAuthorizationUrl() != null)
        && this.responseParams.sawErrorResponse()) {
      this.responseParams.logDetailedWarning(BasicOAuth2Request.classname, "fetchNoThrow",
          MessageKeys.OAUTH_FETCH_ERROR_REPROMPT);
      this.responseParams.setSendTraceToClient(true);
    }

    this.responseParams.addToResponse(response, null);
    return response.create();
  }

  private HttpResponseBuilder fetchWithRetry() throws OAuth2RequestException {
    int attempts = 0;
    boolean retry;
    HttpResponseBuilder response = null;
    do {
      retry = false;
      ++attempts;
      try {
        response = this.attemptFetch();
      } catch (final OAuth2ProtocolException pe) {
        retry = this.handleProtocolException(pe, attempts);
        if (!retry) {
          if (pe.getProblemCode() != null) {
            throw new OAuth2RequestException(pe.getProblemCode(),
                "Service provider rejected request", pe);
          } else {
            throw new OAuth2RequestException(OAuth2Error.UNKNOWN_PROBLEM,
                "Service provider rejected request", pe);
          }
        }
      }
    } while (retry);
    return response;
  }

  private HttpResponseBuilder attemptFetch() throws OAuth2RequestException, OAuth2ProtocolException {
    // Do we have an access token to use?
    if (!BasicOAuth2Request.haveAccessToken(this.accessor)) {
      // We don't have an access token, we need to try and get one
      // First step see if we have a refresh token
      if (BasicOAuth2Request.haveRefreshToken(this.accessor)) {
        // TODO ARC
      } else {
        this.checkCanAuthorize();
        // buildClientApprovalState();
        this.buildAuthorizationUrl();
        this.callbackState.changeState(State.AUTHORIZATION_REQUESTED);

        return new HttpResponseBuilder().setHttpStatusCode(HttpResponse.SC_OK).setStrictNoCache();
      }
    }

    return this.fetchData();
  }

  private void checkCanAuthorize() throws OAuth2RequestException {
    // TODO ARC
    // String pageOwner = realRequest.getSecurityToken().getOwnerId();
    // String pageViewer = realRequest.getSecurityToken().getViewerId();
    // if (pageOwner == null || pageViewer == null) {
    // throw new OAuth2RequestException(OAuth2Error.UNAUTHENTICATED);
    // }
    // if (!fetcherConfig.isViewerAccessTokensEnabled() &&
    // !pageOwner.equals(pageViewer)) {
    // throw new OAuth2RequestException(OAuth2Error.NOT_OWNER);
    // }
  }

  private void buildAuthorizationUrl() throws OAuth2RequestException {
    final String authUrl = this.accessor.getProvider().getAuthorizationUrl();
    if (authUrl == null) {
      throw new OAuth2RequestException(OAuth2Error.BAD_OAUTH_TOKEN_URL, "authorization");
    }

    final String completeAuthUrl = this.getCompleteAuthorizationUrl(authUrl, this.accessor);

    this.responseParams.setAuthorizationUrl(completeAuthUrl);
  }

  private static boolean haveAccessToken(final OAuth2Accessor accessor) {
    boolean ret = false;
    final OAuth2Token accessToken = accessor.getAccessToken();
    if ((accessToken != null)) {
      if (BasicOAuth2Request.validateAccessToken(accessToken)) {
        ret = true;
      }
    }
    return ret;
  }

  private static boolean validateAccessToken(final OAuth2Token accessToken) {
    final boolean ret = true;
    // Nothing really to validate
    return ret;
  }

  private static boolean haveRefreshToken(final OAuth2Accessor accessor) {
    boolean ret = false;
    final OAuth2Token refreshToken = accessor.getRefreshToken();
    if ((refreshToken != null)) {
      if (BasicOAuth2Request.validateRefreshToken(refreshToken)) {
        ret = true;
      }
    }
    return ret;
  }

  private static boolean validateRefreshToken(final OAuth2Token refreshToken) {
    final boolean ret = true;
    // Nothing really to validate
    return ret;
  }

  private HttpRequest createAuthorizationRequest(final OAuth2Accessor accessor)
      throws OAuth2RequestException {
    final String authorizationUrl = accessor.getAuthorizationUrl();
    if (authorizationUrl == null) {
      throw new OAuth2RequestException(OAuth2Error.BAD_OAUTH_TOKEN_URL, "authorizationUrl is null");
    }

    final String completeAuthorizationUrl = this.getCompleteAuthorizationUrl(authorizationUrl,
        accessor);

    final HttpRequest request = new HttpRequest(Uri.parse(completeAuthorizationUrl));
    request.setMethod("GET");
    return request;
  }

  private String getCompleteAuthorizationUrl(final String authorizationUrl,
      final OAuth2Accessor accessor) throws OAuth2RequestException {
    String type = "code";

    switch (accessor.getFlow()) {
    case CODE:
      type = "code";
      break;
    case TOKEN:
      type = "token";
      break;
    default:
      throw new OAuth2RequestException(OAuth2Error.MISSING_OAUTH_PARAMETER,
          "There is no type parameter");
    }

    final Map<String, String> queryParams = new HashMap<String, String>(5);
    queryParams.put("response_type", type);
    queryParams.put("client_id", accessor.getClientId());
    queryParams.put("redirect_uri", accessor.getRedirectUri());
    queryParams.put("state", Integer.toString(accessor.getCallbackState().getStateKey()));
    queryParams.put("scope", accessor.getScope());

    final String ret = OAuth2Utils.buildUrl(authorizationUrl, queryParams, null);

    return ret;
  }

  private HttpResponseBuilder fetchData() throws OAuth2RequestException, OAuth2ProtocolException {
    HttpResponseBuilder builder = null;

    final HttpResponse response = this.fetchFromServer(this.realRequest);

    this.checkForProtocolProblem(response);
    builder = new HttpResponseBuilder(response);

    return builder;
  }

  private HttpResponse fetchFromServer(final HttpRequest request) throws OAuth2RequestException {
    HttpResponse response = null;
    try {
      response = this.fetcher.fetch(request);
      if (response == null) {
        throw new OAuth2RequestException(OAuth2Error.MISSING_SERVER_RESPONSE);
      }
      return response;
    } catch (final GadgetException e) {
      throw new OAuth2RequestException(OAuth2Error.MISSING_SERVER_RESPONSE, "", e);
    } finally {
      this.responseParams.addRequestTrace(request, response);
    }
  }

  private void checkForProtocolProblem(final HttpResponse response) throws OAuth2ProtocolException {
  }

  private boolean handleProtocolException(final OAuth2ProtocolException pe, final int attempts)
      throws OAuth2RequestException {
    return false;
  }
}