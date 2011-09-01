/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2;

import org.apache.shindig.auth.SecurityToken;
import org.apache.shindig.common.crypto.BlobCrypter;
import org.apache.shindig.common.crypto.BlobCrypterException;
import org.apache.shindig.common.uri.Uri;
import org.apache.shindig.common.uri.UriBuilder;
import org.apache.shindig.gadgets.Gadget;
import org.apache.shindig.gadgets.GadgetContext;
import org.apache.shindig.gadgets.LockedDomainService;
import org.apache.shindig.gadgets.http.HttpRequest;
import org.apache.shindig.gadgets.process.ProcessingException;
import org.apache.shindig.gadgets.process.Processor;
import org.apache.shindig.gadgets.servlet.OAuthCallbackServlet;
import org.apache.shindig.gadgets.uri.OAuthUriManager;

import com.google.common.base.Strings;
import com.google.inject.Inject;
import com.google.inject.name.Named;

/**
 * Generates callback URLs for gadgets using OAuth 1.0a. There are three
 * relevant callback URLs:
 * 
 * 1) The consumer key callback URL: registered with service providers when they
 * issue OAuth consumer keys. Application authors will tell us the callback URL
 * to send to the SP when they provide us with their consumer key.
 * 
 * The SP will check that the callback URL we send them matches whatever was
 * preregistered. It would be nice if they didn't do this, but enough do that we
 * support it.
 * 
 * We don't control the consumer key callback URL. Gadget authors need to make
 * sure that it always redirect to the shindig-deployment global callback URL.
 * 
 * 2) Global callback URL: a single callback URL that can be whitelisted by
 * service providers and shared by all gadgets. This keeps service providers
 * (and gadget authors) from needing to be aware of the complexities of which
 * domain a particular gadget actually runs on.
 * 
 * The global callback URL always redirects to the gadget-domain callback URL.
 * 
 * 3) Gadget domain callback URL: URL on the same hostname as the gadget. This
 * URL will pass the oauth_verifier token into the gadget for reuse. (It has to
 * be on the same hostname so that the same-origin policy allows communication.
 * We could use gadgets.rpc, except that because the authorization happens in a
 * popup we've got no good way to do all the gadgets.rpc bootstrapping.)
 * 
 * Here's an example of what you might see happen with these URLs:
 * 
 * Shindig sends request token request to OAuth SP with callback URL of
 * http://gadgetauthor.com/oauthcallback?cs=<blob>
 * 
 * User approves access. OAuth SP redirects to
 * http://gadgetauthor.com/oauthcallback?cs=<blob>&oauth_verifier=<verifier>
 * 
 * gadgauthor.com redirects to deployment global callback URL:
 * http://oauth.shindigexample
 * .com/oauthcallback?cs=<blob>&oauth_verifier=<verifier>
 * 
 * The global callback URL redirects to a gadget-specific callback URL:
 * http://12345.smodules.com/oauthcallback?oauth_verifier=<verifier>
 * 
 * The gadget-specific callback will use window.opener to find the opening
 * gadget and hand it the verified callback URL.
 */

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public class GadgetOAuth2CallbackGenerator implements OAuth2CallbackGenerator {

  private final Processor processor;
  private final LockedDomainService lockedDomainService;
  private final OAuthUriManager oauthUriManager;
  private final BlobCrypter stateCrypter;

  @Inject
  public GadgetOAuth2CallbackGenerator(final Processor processor,
      final LockedDomainService lockedDomainService, final OAuthUriManager oauthUriManager,
      @Named(OAuth2FetcherConfig.OAUTH_STATE_CRYPTER) final BlobCrypter stateCrypter) {
    this.processor = processor;
    this.lockedDomainService = lockedDomainService;
    this.oauthUriManager = oauthUriManager;
    this.stateCrypter = stateCrypter;
  }

  public String generateCallback(final OAuth2FetcherConfig fetcherConfig,
      final String baseCallback, final HttpRequest request,
      final OAuth2ResponseParams responseParams) throws OAuth2RequestException {
    final Uri activeUrl = this.checkGadgetCanRender(request.getSecurityToken(),
        request.getOAuth2Arguments(), responseParams);
    final String gadgetDomainCallback = this.getGadgetDomainCallback(request.getSecurityToken(),
        activeUrl);
    if (gadgetDomainCallback == null) {
      return null;
    }
    return this.generateCallbackForProvider(responseParams, baseCallback, gadgetDomainCallback);
  }

  private Uri checkGadgetCanRender(final SecurityToken securityToken,
      final OAuth2Arguments arguments, final OAuth2ResponseParams responseParams)
      throws OAuth2RequestException {
    try {
      final GadgetContext context = new OAuth2GadgetContext(securityToken, arguments);
      // This feels really heavy-weight, is there a simpler way to figure out if
      // a gadget requires
      // a locked-domain?
      final Gadget gadget = this.processor.process(context);

      final Uri activeUrl = Uri.parse(securityToken.getActiveUrl());
      final String hostname = activeUrl.getAuthority();
      if (!this.lockedDomainService.gadgetCanRender(hostname, gadget, securityToken.getContainer())) {
        throw new OAuth2RequestException(OAuth2Error.UNKNOWN_PROBLEM,
            "Gadget should not be using URL " + activeUrl);
      }
      return activeUrl;
    } catch (final ProcessingException e) {
      throw new OAuth2RequestException(OAuth2Error.UNKNOWN_PROBLEM,
          "Unable to check if gadget is using locked-domain", e);
    }
  }

  private String getGadgetDomainCallback(final SecurityToken securityToken, final Uri activeUrl) {
    Uri gadgetCallback = this.oauthUriManager.makeOAuthCallbackUri(securityToken.getContainer(),
        activeUrl.getAuthority());
    if (gadgetCallback == null) {
      return null;
    }
    if (Strings.isNullOrEmpty(gadgetCallback.getScheme())) {
      gadgetCallback = new UriBuilder(gadgetCallback).setScheme(activeUrl.getScheme()).toUri();
    }
    return gadgetCallback.toString();
  }

  private String generateCallbackForProvider(final OAuth2ResponseParams responseParams,
      final String callbackForProvider, final String gadgetDomainCallback)
      throws OAuth2RequestException {
    final OAuth2CallbackState state = new OAuth2CallbackState(this.stateCrypter);
    state.setRealCallbackUrl(gadgetDomainCallback);
    final UriBuilder callback = UriBuilder.parse(callbackForProvider);
    try {
      callback.addQueryParameter(OAuthCallbackServlet.CALLBACK_STATE_PARAM,
          state.getEncryptedState());
    } catch (final BlobCrypterException e) {
      throw new OAuth2RequestException(OAuth2Error.UNKNOWN_PROBLEM,
          "Failure generating callback URL", e);
    }
    return callback.toString();
  }
}
