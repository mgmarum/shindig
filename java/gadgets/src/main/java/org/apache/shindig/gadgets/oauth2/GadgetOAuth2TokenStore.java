/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2;

import org.apache.shindig.auth.SecurityToken;
import org.apache.shindig.gadgets.GadgetContext;
import org.apache.shindig.gadgets.GadgetException;
import org.apache.shindig.gadgets.GadgetSpecFactory;
import org.apache.shindig.gadgets.http.HttpFetcher;
import org.apache.shindig.gadgets.spec.GadgetSpec;
import org.apache.shindig.gadgets.spec.OAuth2Service;
import org.apache.shindig.gadgets.spec.OAuth2Service.EndPoint;
import org.apache.shindig.gadgets.spec.OAuth2Spec;

import com.google.common.base.Joiner;
import com.google.inject.Inject;

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public class GadgetOAuth2TokenStore {
  private final OAuth2Store store;
  private final GadgetSpecFactory specFactory;

  @Inject
  public GadgetOAuth2TokenStore(final OAuth2Store store, final GadgetSpecFactory specFactory) {
    this.store = store;
    this.specFactory = specFactory;
  }

  public OAuth2Accessor getOAuth2Accessor(final SecurityToken securityToken,
      final OAuth2Arguments arguments, final OAuth2FetcherConfig fetcherConfig,
      final HttpFetcher fetcher) throws OAuth2RequestException {

    if ((this.store == null) || (arguments == null) || (fetcherConfig == null) || (fetcher == null)) {
      throw new OAuth2RequestException(OAuth2Error.UNKNOWN_PROBLEM,
          "OAuth2Accessor missing a param --- store = " + this.store + " , arguments = "
              + arguments + " , fetcherConfig = " + fetcherConfig + " , fetcher = " + fetcher);
    }
    
    final String serviceName = arguments.getServiceName();
    
    OAuth2Provider provider;
    GadgetException gadgetException = null;
    try {
      provider = this.store.getProvider(serviceName);
    } catch (final GadgetException e) {
      gadgetException = e;
      provider = null;
    }

    if (provider == null) {
      throw new OAuth2RequestException(OAuth2Error.UNKNOWN_PROBLEM,
          "OAuth2Accessor unable to retrieve provider " + serviceName,
          gadgetException);

    }

    OAuth2Client client;
    try {
      client = this.store.getClient(provider.getName(), securityToken.getAppUrl());
    } catch (final GadgetException e) {
      gadgetException = e;
      client = null;
    }

    if (client == null) {
      throw new OAuth2RequestException(OAuth2Error.UNKNOWN_PROBLEM,
          "OAuth2Accessor unable to retrieve client " + provider.getName() + " , "
              + securityToken.getAppUrl(), gadgetException);
    }

    final OAuth2SpecInfo specInfo = this.lookupSpecInfo(securityToken, arguments, provider, client);

    if (specInfo == null) {
      throw new OAuth2RequestException(OAuth2Error.UNKNOWN_PROBLEM,
          "OAuth2Accessor unable to retrieve specinfo " + provider.getName() + " , "
              + securityToken.getAppUrl(), gadgetException);
    }

    final OAuth2Accessor ret = new OAuth2Accessor(provider, client, this.store, securityToken,
        fetcher);

    ret.setAuthorizationUrl(specInfo.getAuthorizationUrl());
    ret.setClientId(specInfo.getClientId());
    ret.setRedirectUri(specInfo.getRedirectUri());
    ret.setTokenUrl(specInfo.getTokenUrl());
    ret.setScope(specInfo.getScope());
    ret.setType(client.getType());
    ret.setFlow(client.getFlow());

    try {
      final OAuth2Token accessToken = this.store.getToken(provider.getName(),
          client.getGadgetUri(), securityToken.getViewerId(), specInfo.getScope(),
          OAuth2Token.Type.ACCESS);
      if (accessToken != null) {
        ret.setAccessToken(accessToken);
      }

      final OAuth2Token refreshToken = this.store.getToken(provider.getName(),
          client.getGadgetUri(), securityToken.getViewerId(), specInfo.getScope(),
          OAuth2Token.Type.REFRESH);
      if (refreshToken != null) {
        ret.setRefreshToken(refreshToken);
      }
    } catch (final GadgetException e) {
      throw new OAuth2RequestException(OAuth2Error.UNKNOWN_PROBLEM, "Unable to retrieve token "
          + provider.getName() + " , " + securityToken.getAppUrl(), e);
    }

    return ret;
  }

  private OAuth2SpecInfo lookupSpecInfo(final SecurityToken securityToken,
      final OAuth2Arguments arguments, final OAuth2Provider provider, final OAuth2Client client)
      throws OAuth2RequestException {
    final GadgetSpec spec = this.findSpec(securityToken, arguments);
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

    final String clientId = client.getKey();
    final String redirectUri = client.getRedirectUri();

    String authorizationUrl = null;
    final EndPoint authorizationUrlEndpoint = service.getAuthorizationUrl();
    if (authorizationUrlEndpoint == null) {
      authorizationUrl = provider.getAuthorizationUrl();
    } else {
      authorizationUrl = authorizationUrlEndpoint.url.toString();
    }

    String tokenUrl = null;
    final EndPoint tokenUrlEndpoint = service.getTokenUrl();
    if (tokenUrlEndpoint == null) {
      tokenUrl = provider.getTokenUrl();
    } else {
      tokenUrl = tokenUrlEndpoint.url.toString();
    }

    return new OAuth2SpecInfo(authorizationUrl, clientId, redirectUri, tokenUrl, service.getScope());
  }

  private GadgetSpec findSpec(final SecurityToken securityToken, final OAuth2Arguments arguments)
      throws OAuth2RequestException {
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

  private static class OAuth2SpecInfo {
    private final String authorizationUrl;
    private final String clientId;
    private final String redirectUri;
    private final String tokenUrl;
    private final String scope;

    public OAuth2SpecInfo(final String authorizationUrl, final String clientId,
        final String redirectUri, final String tokenUrl, final String scope) {
      this.authorizationUrl = authorizationUrl;
      this.clientId = clientId;
      this.redirectUri = redirectUri;
      this.tokenUrl = tokenUrl;
      this.scope = scope;
    }

    public String getAuthorizationUrl() {
      return this.authorizationUrl;
    }

    public String getClientId() {
      return this.clientId;
    }

    public String getRedirectUri() {
      return this.redirectUri;
    }

    public String getTokenUrl() {
      return this.tokenUrl;
    }

    public String getScope() {
      return this.scope;
    }
  }
}
