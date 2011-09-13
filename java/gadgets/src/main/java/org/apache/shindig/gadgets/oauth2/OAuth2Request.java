/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2;

import java.util.HashMap;
import java.util.Map;

import org.apache.shindig.common.logging.i18n.MessageKeys;
import org.apache.shindig.common.uri.Uri;
import org.apache.shindig.gadgets.GadgetException;
import org.apache.shindig.gadgets.http.HttpFetcher;
import org.apache.shindig.gadgets.http.HttpRequest;
import org.apache.shindig.gadgets.http.HttpResponse;
import org.apache.shindig.gadgets.http.HttpResponseBuilder;
import org.apache.shindig.gadgets.oauth2.OAuth2CallbackState;
import org.apache.shindig.gadgets.oauth2.OAuth2CallbackState.State;
import org.apache.shindig.gadgets.oauth2.OAuth2Request;

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public class OAuth2Request {
  // class name for logging purpose
  private static final String classname = OAuth2Request.class.getName();

  protected final OAuth2FetcherConfig fetcherConfig;

  private final HttpFetcher fetcher;

  private HttpRequest realRequest;

  private OAuth2ResponseParams responseParams;

  private OAuth2Accessor accessor;

  private OAuth2CallbackState callbackState;

  private boolean refreshTry = false;

  /**
   * @param fetcherConfig
   *          configuration options for the fetcher
   * @param fetcher
   *          fetcher to use for actually making requests
   */
  public OAuth2Request(final OAuth2FetcherConfig fetcherConfig, final HttpFetcher fetcher) {
    this.fetcherConfig = fetcherConfig;
    this.fetcher = fetcher;
  }

  public HttpResponse fetch(final HttpRequest request) {
    return this.fetch(request, false);
  }

  public HttpResponse fetch(final HttpRequest request, final boolean refreshTry) {
    this.realRequest = request;
    this.responseParams = new OAuth2ResponseParams(request.getSecurityToken(), request);
    this.refreshTry = refreshTry;
    try {
      return this.fetchNoThrow();
    } catch (final RuntimeException e) {
      // We log here to record the request/response pairs that created the
      // failure.
      this.responseParams.logDetailedWarning(OAuth2Request.classname, "fetch",
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
        this.responseParams.logDetailedInfo(OAuth2Request.classname, "fetchNoThrow",
            MessageKeys.UNAUTHENTICATED_OAUTH, e);
      } else if (OAuth2Error.BAD_OAUTH_TOKEN_URL.name().equals(e.getError())) {
        this.responseParams.logDetailedInfo(OAuth2Request.classname, "fetchNoThrow",
            MessageKeys.INVALID_OAUTH, e);
      } else {
        this.responseParams.logDetailedWarning(OAuth2Request.classname, "fetchNoThrow",
            MessageKeys.OAUTH_FETCH_FATAL_ERROR, e);
      }
      this.responseParams.setSendTraceToClient(true);
      response = new HttpResponseBuilder().setHttpStatusCode(HttpResponse.SC_FORBIDDEN)
          .setStrictNoCache();
      this.responseParams.addToResponse(response, e);
      return response.create();
    } catch (final Exception e1) {
      e1.printStackTrace(); // TODO ARC
      this.responseParams.logDetailedWarning(OAuth2Request.classname, "fetchNoThrow",
          MessageKeys.OAUTH_FETCH_FATAL_ERROR, e1);
      this.responseParams.setSendTraceToClient(true);
      response = new HttpResponseBuilder().setHttpStatusCode(HttpResponse.SC_FORBIDDEN)
          .setStrictNoCache();
      this.responseParams.addToResponse(response, new OAuth2RequestException("Generic fetch error",
          e1));
      return response.create();
    }

    // OK, got some data back, annotate it as necessary.
    if (response.getHttpStatusCode() >= 400) {
      this.responseParams.logDetailedWarning(OAuth2Request.classname, "fetchNoThrow",
          MessageKeys.OAUTH_FETCH_FATAL_ERROR);

      this.responseParams.setSendTraceToClient(true);
    } else if ((this.responseParams.getAuthorizationUrl() != null)
        && this.responseParams.sawErrorResponse()) {
      this.responseParams.logDetailedWarning(OAuth2Request.classname, "fetchNoThrow",
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
      response = this.attemptFetch();
    } while (retry);
    return response;
  }

  private HttpResponseBuilder attemptFetch() throws OAuth2RequestException {
    // Do we have an access token to use?
    if (OAuth2Request.haveAccessToken(this.accessor) == null) {
      // We don't have an access token, we need to try and get one
      // First step see if we have a refresh token
      if (OAuth2Request.haveRefreshToken(this.accessor) != null) {
        // TODO ARC
        this.checkCanAuthorize();
        this.callbackState.refreshToken();
      } else {
        this.checkCanAuthorize();
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

  private static OAuth2Token haveAccessToken(final OAuth2Accessor accessor) {
    OAuth2Token ret = accessor.getAccessToken();
    if ((ret != null)) {
      if (!OAuth2Request.validateAccessToken(ret)) {
        ret = null;
      }
    }
    return ret;
  }

  private static boolean validateAccessToken(final OAuth2Token accessToken) {
    final boolean ret = true;
    // Nothing really to validate
    return ret;
  }

  private static OAuth2Token haveRefreshToken(final OAuth2Accessor accessor) {
    OAuth2Token ret = accessor.getRefreshToken();
    if ((ret != null)) {
      if (!OAuth2Request.validateRefreshToken(ret)) {
        ret = null;
      }
    }
    return ret;
  }

  private static boolean validateRefreshToken(final OAuth2Token refereshToken) {
    final boolean ret = true;
    // Nothing really to validate
    return ret;
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
    final String redirectUri = accessor.getRedirectUri();
    if ((redirectUri != null) && (redirectUri.length() > 0)) {
      queryParams.put("redirect_uri", redirectUri);
    }
    if (accessor.getCallbackState().getStateKey() != null) {
      final String state = Integer.toString(accessor.getCallbackState().getStateKey());
      if ((state != null) && (state.length() > 0)) {
        queryParams.put("state", state);
      }
    }
    final String scope = accessor.getScope();
    if ((scope != null) && (scope.length() > 0)) {
      queryParams.put("scope", scope);
    }

    final String ret = OAuth2Utils.buildUrl(authorizationUrl, queryParams, null);

    return ret;
  }

  private HttpResponseBuilder fetchData() throws OAuth2RequestException {
    HttpResponseBuilder builder = null;

    final HttpResponse response = this.fetchFromServer(this.realRequest);

    builder = new HttpResponseBuilder(response);

    return builder;
  }

  private HttpResponse fetchFromServer(final HttpRequest request) throws OAuth2RequestException {
    HttpResponse response = null;

    this.addOAuth2Params(request);

    try {
      response = this.fetcher.fetch(request);
      if (response == null) {
        throw new OAuth2RequestException(OAuth2Error.MISSING_SERVER_RESPONSE);
      }

      final int responseCode = response.getHttpStatusCode();
      if (!this.refreshTry && (responseCode >= 400) && (responseCode < 500)) {
        final OAuth2Token accessToken = this.accessor.getAccessToken();
        final OAuth2Token refreshToken = this.accessor.getRefreshToken();
        if ((accessToken != null) && (refreshToken != null)) {
          // We need a refresh, remove the access token and try again
          this.accessor.setAccessToken(null);
          this.accessor.getStore().removeToken(accessToken);
          // make sure if we get a 2nd 401 we don't loop infinitely
          return this.fetch(this.realRequest, true);
        }
      }

      return response;
    } catch (final GadgetException e) {
      throw new OAuth2RequestException(OAuth2Error.MISSING_SERVER_RESPONSE, "", e);
    } finally {
      this.responseParams.addRequestTrace(request, response);
    }
  }

  private void addOAuth2Params(final HttpRequest request) throws OAuth2RequestException {
    final Uri unAuthorizedRequestUri = request.getUri();
    if (unAuthorizedRequestUri == null) {
      throw new OAuth2RequestException(OAuth2Error.UNKNOWN_PROBLEM, "Uri is null??");
    }

    final OAuth2Token accessToken = this.accessor.getAccessToken();

    final Map<String, String> queryParams = new HashMap<String, String>(1);
    queryParams.put(OAuth2Message.ACCESS_TOKEN, accessToken.getSecret());
    final String authorizedUriString = OAuth2Utils.buildUrl(unAuthorizedRequestUri.toString(),
        queryParams, null);

    request.setUri(Uri.parse(authorizedUriString));

    String tokenType = "Bearer";

    if ((accessToken.getTokenType() != null) && (accessToken.getTokenType().length() > 0)) {
      tokenType = accessToken.getTokenType();
    }

    if (tokenType.equalsIgnoreCase("Bearer")) {
      request.setHeader("Authorization", "Bearer " + accessToken.getSecret());
    } else if (tokenType.equalsIgnoreCase("mac")) {
      throw new RuntimeException("@@@ TODO ARC implement mac token type");
    } else {
      throw new OAuth2RequestException(OAuth2Error.UNKNOWN_PROBLEM, "Unknow tokey type "
          + tokenType);
    }
  }
}