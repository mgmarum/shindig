/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2;

import org.apache.shindig.auth.SecurityToken;
import org.apache.shindig.common.uri.Uri;
import org.apache.shindig.gadgets.GadgetContext;
import org.apache.shindig.gadgets.GadgetException;
import org.apache.shindig.gadgets.GadgetSpecFactory;
import org.apache.shindig.gadgets.oauth.OAuthStore.ConsumerInfo;
import org.apache.shindig.gadgets.oauth2.AccessorInfo.HttpMethod;
import org.apache.shindig.gadgets.oauth2.AccessorInfo.OAuth2ParamLocation;
import org.apache.shindig.gadgets.oauth2.core.OAuth2Consumer;
import org.apache.shindig.gadgets.oauth2.core.OAuth2ServiceProvider;
import org.apache.shindig.gadgets.oauth2.core.Token;
import org.apache.shindig.gadgets.spec.GadgetSpec;
import org.apache.shindig.gadgets.spec.OAuth2Service;
import org.apache.shindig.gadgets.spec.OAuth2Spec;
import org.apache.shindig.gadgets.spec.OAuth2Service.Location;
import org.apache.shindig.gadgets.spec.OAuth2Service.Method;
import org.apache.shindig.gadgets.spec.SpecParserException;


import com.google.common.base.Joiner;
import com.google.inject.Inject;

/**
 * Higher-level interface that allows callers to store and retrieve
 * OAuth-related data directly from {@code GadgetSpec}s, {@code GadgetContext}s,
 * etc. See {@link OAuth2Store} for a more detailed explanation of the OAuth
 * Data Store.
 */

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public class GadgetOAuth2TokenStore {

  private final OAuth2Store store;
  private final GadgetSpecFactory specFactory;

  /**
   * Public constructor.
   * 
   * @param store
   *          an {@link OAuth2Store} that can store and retrieve OAuth tokens,
   *          as well as information about service providers.
   */
  @Inject
  public GadgetOAuth2TokenStore(final OAuth2Store store, final GadgetSpecFactory specFactory) {
    this.store = store;
    this.specFactory = specFactory;
  }

  /**
   * Retrieve an AccessorInfo and OAuthAccessor that are ready for signing
   * OAuthMessages. To do this, we need to figure out:
   * 
   * - what consumer key/secret to use for signing. - if an access token should
   * be used for the request, and if so what it is. * - the OAuth
   * request/authorization/access URLs. - what HTTP method to use for request
   * token and access token requests - where the OAuth parameters are located. -
   * Information from the OAuth Fetcher config to determine if owner pages are
   * secure
   * 
   * Note that most of that work gets skipped for signed fetch, we just look up
   * the consumer key and secret for that. Signed fetch always sticks the
   * parameters in the query string.
   */
  public AccessorInfo getOAuthAccessor(final SecurityToken securityToken,
      final OAuth2Arguments arguments, final OAuth2ClientState clientState,
      final OAuth2ResponseParams responseParams, final OAuth2FetcherConfig fetcherConfig)
      throws OAuth2RequestException {

    final AccessorInfoBuilder accessorBuilder = new AccessorInfoBuilder();

    // Pick up any additional information needed about the format of the
    // request, either from
    // options to makeRequest, or options from the spec, or from sensible
    // defaults. This is how
    // we figure out where to put the OAuth parameters and what methods to use
    // for the OAuth
    // URLs.
    OAuth2ServiceProvider provider = null;
    if (arguments.programmaticConfig()) {
      provider = this.loadProgrammaticConfig(arguments, accessorBuilder, responseParams);
    } else if (arguments.mayUseToken()) {
      provider = this.lookupSpecInfo(securityToken, arguments, accessorBuilder, responseParams);
    } else {
      // This is plain old signed fetch.
      accessorBuilder.setParameterLocation(AccessorInfo.OAuth2ParamLocation.URI_QUERY);
    }

    // What consumer key/secret should we use?
    //todo !!!
    //Consumer consumer;
    /*
    ConsumerInfo consumer;
    try {
      consumer = this.store.getConsumerKeyAndSecret(securityToken, arguments.getServiceName(),
          provider);
     consumer = null;
      
      //accessorBuilder.setConsumer(consumer);
      accessorBuilder.setConsumer(consumer);
    } catch (final GadgetException e) {
      throw new OAuth2RequestException(OAuth2Error.UNKNOWN_PROBLEM,
          "Unable to retrieve consumer key", e);
    }
    */

    // Should we use the OAuth access token? We never do this unless the client
    // allows it, and
    // if owner == viewer or owner pages are secure.
    if (arguments.mayUseToken() && (securityToken.getViewerId() != null)) {
      if (((fetcherConfig != null) && fetcherConfig.isViewerAccessTokensEnabled())
          || securityToken.getViewerId().equals(securityToken.getOwnerId())) {
    	//todo !!! fake my token here!!!  
        /*this.lookupToken(securityToken, consumer, arguments, clientState, accessorBuilder,
            responseParams);*/
      }
    }

    return accessorBuilder.create(responseParams);
  }

  /**
   * Lookup information contained in the gadget spec.
   */
  private OAuth2ServiceProvider lookupSpecInfo(final SecurityToken securityToken,
      final OAuth2Arguments arguments, final AccessorInfoBuilder accessorBuilder,
      final OAuth2ResponseParams responseParams) throws OAuth2RequestException {
    final GadgetSpec spec = this.findSpec(securityToken, arguments, responseParams);
    final OAuth2Spec oauthSpec = spec.getModulePrefs().getOAuth2Spec();
    if (oauthSpec == null) {
      throw new OAuth2RequestException(OAuth2Error.BAD_OAUTH_CONFIGURATION,
          "Failed to retrieve OAuth URLs, spec for gadget " + securityToken.getAppUrl()
              + " does not contain OAuth element.");
    }
    final OAuth2Service service = oauthSpec.getServices().get(arguments.getServiceName());
    if (service == null) {
      throw new OAuth2RequestException(OAuth2Error.BAD_OAUTH_CONFIGURATION,
          "Failed to retrieve OAuth URLs, spec for gadget does not contain OAuth service "
              + arguments.getServiceName() + ".  Known services: "
              + Joiner.on(',').join(oauthSpec.getServices().keySet()) + '.');
    }

    accessorBuilder.setParameterLocation(
    		getStoreLocation(service.getAuthorizationUrl().location, responseParams));
    accessorBuilder.setMethod(
    		getStoreMethod(service.getAuthorizationUrl().method, responseParams));

    return new OAuth2ServiceProvider(
    		service.getAuthorizationUrl().url.toJavaUri().toASCIIString(),
    		service.getTokenUrl().url.toJavaUri().toASCIIString());
  }

  private OAuth2ServiceProvider loadProgrammaticConfig(final OAuth2Arguments arguments,
      final AccessorInfoBuilder accessorBuilder, final OAuth2ResponseParams responseParams)
      throws OAuth2RequestException {
    try {
      final String paramLocationStr = arguments.getRequestOption(
          OAuth2Arguments.PARAM_LOCATION_PARAM, "");
      final Location l = Location.parse(paramLocationStr);
      accessorBuilder.setParameterLocation(this.getStoreLocation(l, responseParams));

      final String requestMethod = arguments.getRequestOption(OAuth2Arguments.REQUEST_METHOD_PARAM,
          "GET");
      final Method m = Method.parse(requestMethod);
      accessorBuilder.setMethod(this.getStoreMethod(m, responseParams));

      final String requestTokenUrl = arguments
          .getRequestOption(OAuth2Arguments.REQUEST_TOKEN_URL_PARAM);
      this.verifyUrl(requestTokenUrl, responseParams);
      final String accessTokenUrl = arguments
          .getRequestOption(OAuth2Arguments.ACCESS_TOKEN_URL_PARAM);
      this.verifyUrl(accessTokenUrl, responseParams);

      final String authorizationUrl = arguments
          .getRequestOption(OAuth2Arguments.AUTHORIZATION_URL_PARAM);
      this.verifyUrl(authorizationUrl, responseParams);
      return null; // TODO new OAuth2ServiceProvider(requestTokenUrl,
                   // authorizationUrl, accessTokenUrl);
    } catch (final SpecParserException e) {
      // these exceptions have decent programmer readable messages
      throw new OAuth2RequestException(OAuth2Error.BAD_OAUTH_CONFIGURATION, e.getMessage());
    }
  }

  private void verifyUrl(final String url, final OAuth2ResponseParams responseParams)
      throws OAuth2RequestException {
    if (url == null) {
      return;
    }
    Uri uri;
    try {
      uri = Uri.parse(url);
    } catch (final Throwable t) {
      throw new OAuth2RequestException(OAuth2Error.INVALID_URL, url);
    }
    if (!uri.isAbsolute()) {
      throw new OAuth2RequestException(OAuth2Error.INVALID_URL, url);
    }
  }

  /**
   * Figure out the OAuth token that should be used with this request. We check
   * for this in three places. In order of priority:
   * 
   * 1) From information we cached on the client. We encrypt the token and cache
   * on the client for performance.
   * 
   * 2) From information we have in our persistent state. We persist the token
   * server-side so we can look it up if necessary.
   * 
   * 3) From information the gadget developer tells us to use (a preapproved
   * request token.) Gadgets can be initialized with preapproved request tokens.
   * If the user tells the service provider they want to add a gadget to a
   * gadget container site, the service provider can create a preapproved
   * request token for that site and pass it to the gadget as a user preference.
   */
  private void lookupToken(final SecurityToken securityToken, final OAuth2Consumer consumer,
      final OAuth2Arguments arguments, final OAuth2ClientState clientState,
      final AccessorInfoBuilder accessorBuilder, final OAuth2ResponseParams responseParams)
      throws OAuth2RequestException {
   /* if (clientState.getRequestToken() != null) {
      // We cached the request token on the client.
      //accessorBuilder.setRequestToken(clientState.getRequestToken());
      //accessorBuilder.setTokenSecret(clientState.getRequestTokenSecret());
    } else */if (clientState.getAccessToken() != null) {
      // We cached the access token on the client
      accessorBuilder.setAccessToken(clientState.getAccessToken());
      accessorBuilder.setTokenSecret(clientState.getAccessTokenSecret());
      accessorBuilder.setSessionHandle(clientState.getSessionHandle());
      accessorBuilder.setTokenExpireMillis(clientState.getTokenExpireMillis());
    } else {
      // No useful client-side state, check persistent storage
      Token tokenInfo;
      try {
        tokenInfo = this.store.getTokenInfo(securityToken, consumer, arguments.getServiceName(),
           arguments.getTokenName());
      } catch (final GadgetException e) {
        throw new OAuth2RequestException(OAuth2Error.UNKNOWN_PROBLEM,
            "Unable to retrieve access token", e);
      }
      if ((tokenInfo != null) && (tokenInfo.getAccessToken() != null)) {
        // We have an access token in persistent storage, use that.
        accessorBuilder.setAccessToken(tokenInfo.getAccessToken());
        accessorBuilder.setTokenSecret(tokenInfo.getSecret());
        accessorBuilder.setSessionHandle(tokenInfo.getSessionHandle());
        accessorBuilder.setTokenExpireMillis(tokenInfo.getTokenExpireMillis());
      } /*else {
        // We don't have an access token yet, but the client sent us a
        // (hopefully) preapproved
        // request token.
        //accessorBuilder.setRequestToken(arguments.getRequestToken());
        accessorBuilder.setTokenSecret(arguments.getRequestTokenSecret());
      }*/
    }
  }

  private OAuth2ParamLocation getStoreLocation(final Location location,
      final OAuth2ResponseParams responseParams) throws OAuth2RequestException {
    switch (location) {
    case HEADER:
      return OAuth2ParamLocation.AUTH_HEADER;
    case URL:
      return OAuth2ParamLocation.URI_QUERY;
    case BODY:
      return OAuth2ParamLocation.POST_BODY;
    }
    throw new OAuth2RequestException(OAuth2Error.UNKNOWN_PARAMETER_LOCATION);
  }

  private HttpMethod getStoreMethod(final Method method, final OAuth2ResponseParams responseParams)
      throws OAuth2RequestException {
    switch (method) {
    case GET:
      return HttpMethod.GET;
    case POST:
      return HttpMethod.POST;
    }
    throw new OAuth2RequestException(OAuth2Error.UNSUPPORTED_HTTP_METHOD, method.toString());
  }

  private GadgetSpec findSpec(final SecurityToken securityToken, final OAuth2Arguments arguments,
      final OAuth2ResponseParams responseParams) throws OAuth2RequestException {
    try {
      final GadgetContext context = new OAuth2GadgetContext(securityToken, arguments);
      return this.specFactory.getGadgetSpec(context);
    } catch (final IllegalArgumentException e) {
      throw new OAuth2RequestException(OAuth2Error.UNKNOWN_PROBLEM,
          "Could not fetch gadget spec, gadget URI invalid.", e);
    } catch (final GadgetException e) {
      throw new OAuth2RequestException(OAuth2Error.UNKNOWN_PROBLEM, "Could not fetch gadget spec",
          e);
    }
  }

  /**
   * Store an access token for the given user/gadget/service/token name
   */
  public void storeTokenKeyAndSecret(final SecurityToken securityToken, final OAuth2Consumer consumer,
      final OAuth2Arguments arguments, final Token tokenInfo,
      final OAuth2ResponseParams responseParams) throws OAuth2RequestException {
    try {
      this.store.setTokenInfo(securityToken, consumer, arguments.getServiceName(),
          arguments.getTokenName(), tokenInfo);
    } catch (final GadgetException e) {
      throw new OAuth2RequestException(OAuth2Error.UNKNOWN_PROBLEM, "Unable to store access token",
          e);
    }
  }

  /**
   * Remove an access token for the given user/gadget/service/token name
   */
  public void removeToken(final SecurityToken securityToken, final ConsumerInfo consumer,
      final OAuth2Arguments arguments, final OAuth2ResponseParams responseParams)
      throws OAuth2RequestException {
    /*try {
     //todo !!!
    	this.store.removeToken(securityToken, consumer, arguments.getServiceName(),
          arguments.getTokenName());
    } catch (final GadgetException e) {
      throw new OAuth2RequestException(OAuth2Error.UNKNOWN_PROBLEM,
          "Unable to remove access token", e);
    }*/
	     throw new OAuth2RequestException(OAuth2Error.UNKNOWN_PROBLEM,
	             "Unable to remove access token");
	    
  }
}
