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

/**
 * GadgetContext for use when handling an OAuth request.
 */

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public class OAuth2GadgetContext extends GadgetContext {

  private final SecurityToken securityToken;
  private final String container;
  private final Uri appUrl;
  private final boolean bypassSpecCache;

  public OAuth2GadgetContext(final SecurityToken securityToken, final OAuth2Arguments arguments) {
    this.securityToken = securityToken;
    this.container = securityToken.getContainer();
    this.appUrl = Uri.parse(securityToken.getAppUrl());
    this.bypassSpecCache = arguments.getBypassSpecCache();
  }

  @Override
  public String getContainer() {
    return this.container;
  }

  @Override
  public SecurityToken getToken() {
    return this.securityToken;
  }

  @Override
  public Uri getUrl() {
    return this.appUrl;
  }

  @Override
  public boolean getIgnoreCache() {
    return this.bypassSpecCache;
  }
}
