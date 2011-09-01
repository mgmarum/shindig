/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2;

import java.util.Enumeration;
import java.util.Map;
import java.util.TreeMap;

import javax.servlet.http.HttpServletRequest;

import org.apache.shindig.gadgets.AuthType;
import org.apache.shindig.gadgets.GadgetException;
import org.apache.shindig.gadgets.http.HttpResponse;
import org.apache.shindig.gadgets.spec.RequestAuthenticationInfo;

import com.google.common.base.Objects;

/**
 * Arguments to an OAuth fetch sent by the client.
 */

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public class OAuth2Arguments {
  private static final String SERVICE_PARAM = "OAUTH_SERVICE_NAME";
  private static final String TOKEN_PARAM = "OAUTH_TOKEN_NAME";
  private static final String REQUEST_TOKEN_PARAM = "OAUTH_REQUEST_TOKEN";
  private static final String REQUEST_TOKEN_SECRET_PARAM = "OAUTH_REQUEST_TOKEN_SECRET";
  private static final String USE_TOKEN_PARAM = "OAUTH_USE_TOKEN";
  private static final String CLIENT_STATE_PARAM = "oauthState";
  private static final String BYPASS_SPEC_CACHE_PARAM = "bypassSpecCache";
  private static final String SIGN_OWNER_PARAM = "signOwner";
  private static final String SIGN_VIEWER_PARAM = "signViewer";
  private static final String RECEIVED_CALLBACK_PARAM = "OAUTH_RECEIVED_CALLBACK";

  // Experimental support for configuring OAuth without special parameters in
  // the spec XML.
  public static final String PROGRAMMATIC_CONFIG_PARAM = "OAUTH_PROGRAMMATIC_CONFIG";
  public static final String REQUEST_METHOD_PARAM = "OAUTH_REQUEST_METHOD";
  public static final String PARAM_LOCATION_PARAM = "OAUTH_PARAM_LOCATION";
  public static final String REQUEST_TOKEN_URL_PARAM = "OAUTH_REQUEST_TOKEN_URL";
  public static final String ACCESS_TOKEN_URL_PARAM = "OAUTH_ACCESS_TOKEN_URL";
  public static final String AUTHORIZATION_URL_PARAM = "OAUTH_AUTHORIZATION_URL";

  /**
   * Should the OAuth access token be used?
   */
  public static enum UseToken {
    /** Do not use the OAuth access token */
    NEVER,
    /**
     * Use the access token if it exists already, but don't prompt for
     * permission
     */
    IF_AVAILABLE,
    /** Use the access token if it exists, and prompt if it doesn't */
    ALWAYS,
  }

  /** Should we attempt to use an access token for the request */
  private UseToken useToken = UseToken.ALWAYS;

  /** OAuth service nickname. Signed fetch uses the empty string */
  private String serviceName = "";

  /** OAuth token nickname. Signed fetch uses the empty string */
  private String tokenName = "";

  /** Request token the client wants us to use, may be null */
  private String requestToken = null;

  /** Token secret that goes with the request token */
  private String requestTokenSecret = null;

  /** Encrypted state blob stored on the client */
  private String origClientState = null;

  /** Whether we should bypass the gadget spec cache */
  private boolean bypassSpecCache = false;

  /** Include information about the owner? */
  private boolean signOwner = false;

  /** Include information about the viewer? */
  private boolean signViewer = false;

  /** Arbitrary name/value pairs associated with the request */
  private final Map<String, String> requestOptions = new TreeMap<String, String>(
      String.CASE_INSENSITIVE_ORDER);

  /** Whether the request is one for proxied content */
  private boolean proxiedContentRequest = false;

  /** Callback URL returned from service provider */
  private String receivedCallbackUrl = null;

  /**
   * Parse OAuthArguments from parameters to the makeRequest servlet.
   * 
   * @param auth
   *          authentication type for the request
   * @param request
   *          servlet request
   * @throws GadgetException
   *           if any parameters are invalid.
   */
  public OAuth2Arguments(final AuthType auth, final HttpServletRequest request)
      throws GadgetException {
    this.useToken = OAuth2Arguments.parseUseToken(auth,
        OAuth2Arguments.getRequestParam(request, OAuth2Arguments.USE_TOKEN_PARAM, ""));
    this.serviceName = OAuth2Arguments.getRequestParam(request, OAuth2Arguments.SERVICE_PARAM, "");
    this.tokenName = OAuth2Arguments.getRequestParam(request, OAuth2Arguments.TOKEN_PARAM, "");
    this.requestToken = OAuth2Arguments.getRequestParam(request,
        OAuth2Arguments.REQUEST_TOKEN_PARAM, null);
    this.requestTokenSecret = OAuth2Arguments.getRequestParam(request,
        OAuth2Arguments.REQUEST_TOKEN_SECRET_PARAM, null);
    this.origClientState = OAuth2Arguments.getRequestParam(request,
        OAuth2Arguments.CLIENT_STATE_PARAM, null);
    this.bypassSpecCache = "1".equals(OAuth2Arguments.getRequestParam(request,
        OAuth2Arguments.BYPASS_SPEC_CACHE_PARAM, null));
    this.signOwner = Boolean.parseBoolean(OAuth2Arguments.getRequestParam(request,
        OAuth2Arguments.SIGN_OWNER_PARAM, "true"));
    this.signViewer = Boolean.parseBoolean(OAuth2Arguments.getRequestParam(request,
        OAuth2Arguments.SIGN_VIEWER_PARAM, "true"));
    this.receivedCallbackUrl = OAuth2Arguments.getRequestParam(request,
        OAuth2Arguments.RECEIVED_CALLBACK_PARAM, null);
    final Enumeration<String> params = this.getParameterNames(request);
    while (params.hasMoreElements()) {
      final String name = params.nextElement();
      this.requestOptions.put(name, request.getParameter(name));
    }
  }

  @SuppressWarnings("unchecked")
  private Enumeration<String> getParameterNames(final HttpServletRequest request) {
    return request.getParameterNames();
  }

  /**
   * Parse OAuthArguments from parameters to Preload, proxied content rendering,
   * and OSML tags.
   */
  public OAuth2Arguments(final RequestAuthenticationInfo info) throws GadgetException {
    this(info.getAuthType(), info.getAttributes());

    this.origClientState = null; // Client has no state for declarative calls
    this.bypassSpecCache = false; // too much trouble to copy nocache=1 from the
                                  // request context to here.

    this.signOwner = info.isSignOwner();
    this.signViewer = info.isSignViewer();
  }

  /**
   * Parse OAuthArguments from a Map of settings
   */
  public OAuth2Arguments(final AuthType auth, final Map<String, String> map) throws GadgetException {
    this.requestOptions.putAll(map);
    this.useToken = OAuth2Arguments.parseUseToken(auth,
        OAuth2Arguments.getAuthInfoParam(this.requestOptions, OAuth2Arguments.USE_TOKEN_PARAM, ""));
    this.serviceName = OAuth2Arguments.getAuthInfoParam(this.requestOptions,
        OAuth2Arguments.SERVICE_PARAM, "");
    this.tokenName = OAuth2Arguments.getAuthInfoParam(this.requestOptions,
        OAuth2Arguments.TOKEN_PARAM, "");
    this.requestToken = OAuth2Arguments.getAuthInfoParam(this.requestOptions,
        OAuth2Arguments.REQUEST_TOKEN_PARAM, null);
    this.requestTokenSecret = OAuth2Arguments.getAuthInfoParam(this.requestOptions,
        OAuth2Arguments.REQUEST_TOKEN_SECRET_PARAM, null);
    this.origClientState = OAuth2Arguments.getAuthInfoParam(this.requestOptions,
        OAuth2Arguments.CLIENT_STATE_PARAM, null);
    this.bypassSpecCache = "1".equals(OAuth2Arguments.getAuthInfoParam(this.requestOptions,
        OAuth2Arguments.BYPASS_SPEC_CACHE_PARAM, null));
    this.signOwner = Boolean.parseBoolean(OAuth2Arguments.getAuthInfoParam(this.requestOptions,
        OAuth2Arguments.SIGN_OWNER_PARAM, "true"));
    this.signViewer = Boolean.parseBoolean(OAuth2Arguments.getAuthInfoParam(this.requestOptions,
        OAuth2Arguments.SIGN_VIEWER_PARAM, "true"));
    this.receivedCallbackUrl = OAuth2Arguments.getAuthInfoParam(this.requestOptions,
        OAuth2Arguments.RECEIVED_CALLBACK_PARAM, null);
  }

  /**
   * @return the named attribute from the Preload tag attributes, or default if
   *         the attribute is not present.
   */
  private static String getAuthInfoParam(final Map<String, String> attrs, final String name,
      final String def) {
    String val = attrs.get(name);
    if (val == null) {
      val = def;
    }
    return val;
  }

  /**
   * @return the named parameter from the request, or default if the named
   *         parameter is not present.
   */
  private static String getRequestParam(final HttpServletRequest request, final String name,
      final String def) {
    String val = request.getParameter(name);
    if (val == null) {
      val = def;
    }
    return val;
  }

  /**
   * Figure out what the client wants us to do with the OAuth access token.
   */
  private static UseToken parseUseToken(final AuthType auth, String useTokenStr)
      throws GadgetException {
    if (useTokenStr.length() == 0) {
      if (auth == AuthType.SIGNED) {
        // signed fetch defaults to not using the token
        return UseToken.NEVER;
      } else {
        // OAuth defaults to always using it.
        return UseToken.ALWAYS;
      }
    }
    useTokenStr = useTokenStr.toLowerCase();
    if ("always".equals(useTokenStr)) {
      return UseToken.ALWAYS;
    }
    if ("if_available".equals(useTokenStr)) {
      return UseToken.IF_AVAILABLE;
    }
    if ("never".equals(useTokenStr)) {
      return UseToken.NEVER;
    }
    throw new GadgetException(GadgetException.Code.INVALID_PARAMETER, "Unknown use token value "
        + useTokenStr, HttpResponse.SC_BAD_REQUEST);
  }

  /**
   * Create an OAuthArguments object with all default values. The details can be
   * filled in later using the setters.
   * 
   * Be careful using this in anything except test code. If you find yourself
   * wanting to use this method in real code, consider writing a new constructor
   * instead.
   */
  public OAuth2Arguments() {
  }

  /**
   * Copy constructor.
   */
  public OAuth2Arguments(final OAuth2Arguments orig) {
    this.useToken = orig.useToken;
    this.serviceName = orig.serviceName;
    this.tokenName = orig.tokenName;
    this.requestToken = orig.requestToken;
    this.requestTokenSecret = orig.requestTokenSecret;
    this.origClientState = orig.origClientState;
    this.bypassSpecCache = orig.bypassSpecCache;
    this.signOwner = orig.signOwner;
    this.signViewer = orig.signViewer;
    this.requestOptions.putAll(orig.requestOptions);
    this.proxiedContentRequest = orig.proxiedContentRequest;
  }

  public boolean mustUseToken() {
    return (this.useToken == UseToken.ALWAYS);
  }

  public boolean mayUseToken() {
    return ((this.useToken == UseToken.IF_AVAILABLE) || (this.useToken == UseToken.ALWAYS));
  }

  public UseToken getUseToken() {
    return this.useToken;
  }

  public void setUseToken(final UseToken useToken) {
    this.useToken = useToken;
  }

  public String getServiceName() {
    return this.serviceName;
  }

  public void setServiceName(final String serviceName) {
    this.serviceName = serviceName;
  }

  public String getTokenName() {
    return this.tokenName;
  }

  public void setTokenName(final String tokenName) {
    this.tokenName = tokenName;
  }

  public String getRequestToken() {
    return this.requestToken;
  }

  public void setRequestToken(final String requestToken) {
    this.requestToken = requestToken;
  }

  public String getRequestTokenSecret() {
    return this.requestTokenSecret;
  }

  public void setRequestTokenSecret(final String requestTokenSecret) {
    this.requestTokenSecret = requestTokenSecret;
  }

  public String getOrigClientState() {
    return this.origClientState;
  }

  public void setOrigClientState(final String origClientState) {
    this.origClientState = origClientState;
  }

  public boolean getBypassSpecCache() {
    return this.bypassSpecCache;
  }

  public void setBypassSpecCache(final boolean bypassSpecCache) {
    this.bypassSpecCache = bypassSpecCache;
  }

  public boolean getSignOwner() {
    return this.signOwner;
  }

  public void setSignOwner(final boolean signOwner) {
    this.signOwner = signOwner;
  }

  public boolean getSignViewer() {
    return this.signViewer;
  }

  public void setSignViewer(final boolean signViewer) {
    this.signViewer = signViewer;
  }

  public void setRequestOption(final String name, final String value) {
    this.requestOptions.put(name, value);
  }

  public void removeRequestOption(final String name) {
    this.requestOptions.remove(name);
  }

  public String getRequestOption(final String name) {
    return this.requestOptions.get(name);
  }

  public String getRequestOption(final String name, final String def) {
    final String val = this.requestOptions.get(name);
    return (val != null ? val : def);
  }

  public boolean isProxiedContentRequest() {
    return this.proxiedContentRequest;
  }

  public void setProxiedContentRequest(final boolean proxiedContentRequest) {
    this.proxiedContentRequest = proxiedContentRequest;
  }

  public boolean programmaticConfig() {
    return Boolean.parseBoolean(this.requestOptions.get(OAuth2Arguments.PROGRAMMATIC_CONFIG_PARAM));
  }

  public String getReceivedCallbackUrl() {
    return this.receivedCallbackUrl;
  }

  public void setReceivedCallbackUrl(final String receivedCallbackUrl) {
    this.receivedCallbackUrl = receivedCallbackUrl;
  }

  @Override
  public int hashCode() {
    return Objects.hashCode(this.bypassSpecCache, this.origClientState, this.origClientState,
        this.proxiedContentRequest, this.requestToken, this.requestTokenSecret,
        this.requestTokenSecret, this.serviceName, this.serviceName, this.signOwner,
        this.signViewer, this.tokenName, this.useToken);
  }

  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }

    if (!(obj instanceof OAuth2Arguments)) {
      return false;
    }

    final OAuth2Arguments other = (OAuth2Arguments) obj;
    return ((this.bypassSpecCache == other.bypassSpecCache)
        && Objects.equal(this.origClientState, other.origClientState)
        && (this.proxiedContentRequest == other.proxiedContentRequest)
        && Objects.equal(this.requestToken, other.requestToken)
        && Objects.equal(this.requestTokenSecret, other.requestTokenSecret)
        && Objects.equal(this.tokenName, other.tokenName) && (this.signViewer == other.signViewer) && (this.useToken == other.useToken));
  }
}
