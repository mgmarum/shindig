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

  public OAuth2Store getOAuth2Store() {
    return this.store;
  }

  public OAuth2Accessor getOAuth2Accessor(final SecurityToken securityToken,
      final OAuth2Arguments arguments, final Uri gadgetUri) throws OAuth2RequestException {

    if ((this.store == null) || (gadgetUri == null) || (securityToken == null)) {
      throw new OAuth2RequestException(OAuth2Error.UNKNOWN_PROBLEM,
          "OAuth2Accessor missing a param --- store = " + this.store + " , gadgetUri = "
              + gadgetUri + " , securityToken = " + securityToken);
    }

    final String serviceName = arguments.getServiceName();

    final OAuth2SpecInfo specInfo = this.lookupSpecInfo(securityToken, arguments, gadgetUri);

    if (specInfo == null) {
      throw new OAuth2RequestException(OAuth2Error.UNKNOWN_PROBLEM,
          "OAuth2Accessor unable to retrieve specinfo " + gadgetUri.toString() + " , "
              + arguments.getServiceName());
    }

    String scope = arguments.getScope();
    if ((scope == null) || (scope.length() == 0)) {
      // no scope on request, default to module prefs scope
      scope = specInfo.getScope();
    }

    if ((scope == null) || (scope.length() == 0)) {
      scope = "";
    }

    OAuth2Accessor persistedAccessor;
    try {
      persistedAccessor = this.store.getOAuth2Accessor(gadgetUri.toString(), serviceName,
          securityToken.getViewerId(), scope);
    } catch (final GadgetException e) {
      persistedAccessor = null;
    }

    if (persistedAccessor == null) {
      throw new OAuth2RequestException(OAuth2Error.UNKNOWN_PROBLEM,
          "getOAuth2Accessor() unable to retrieve accessor " + serviceName + " , "
              + gadgetUri.toString());
    }

    final OAuth2Accessor mergedAccessor = new BasicOAuth2Accessor(persistedAccessor);

    if (persistedAccessor.isAllowModuleOverrides()) {
      final String specAuthorizationUrl = specInfo.getAuthorizationUrl();
      final String specTokenUrl = specInfo.getTokenUrl();

      if ((specAuthorizationUrl != null) && (specAuthorizationUrl.length() > 0)) {
        mergedAccessor.setAuthorizationUrl(specAuthorizationUrl);
      }
      if ((specTokenUrl != null) && (specTokenUrl.length() > 0)) {
        mergedAccessor.setTokenUrl(specTokenUrl);
      }
    }

    this.store.storeOAuth2Accessor(mergedAccessor);

    return mergedAccessor;
  }

  private OAuth2SpecInfo lookupSpecInfo(final SecurityToken securityToken,
      final OAuth2Arguments arguments, final Uri gadgetUri) throws OAuth2RequestException {
    final GadgetSpec spec = this.findSpec(securityToken, arguments, gadgetUri);
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

    String authorizationUrl = null;
    final EndPoint authorizationUrlEndpoint = service.getAuthorizationUrl();
    if (authorizationUrlEndpoint != null) {
      authorizationUrl = authorizationUrlEndpoint.url.toString();
    }

    String tokenUrl = null;
    final EndPoint tokenUrlEndpoint = service.getTokenUrl();
    if (tokenUrlEndpoint != null) {
      tokenUrl = tokenUrlEndpoint.url.toString();
    }

    return new OAuth2SpecInfo(authorizationUrl, tokenUrl, service.getScope());
  }

  private GadgetSpec findSpec(final SecurityToken securityToken, final OAuth2Arguments arguments,
      final Uri gadgetUri) throws OAuth2RequestException {
    try {
      final GadgetContext context = new OAuth2GadgetContext(securityToken, arguments, gadgetUri);
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
    private final String tokenUrl;
    private final String scope;

    public OAuth2SpecInfo(final String authorizationUrl, final String tokenUrl, final String scope) {
      this.authorizationUrl = authorizationUrl;
      this.tokenUrl = tokenUrl;
      this.scope = scope;
    }

    public String getAuthorizationUrl() {
      return this.authorizationUrl;
    }

    public String getTokenUrl() {
      return this.tokenUrl;
    }

    public String getScope() {
      return this.scope;
    }
  }
}
