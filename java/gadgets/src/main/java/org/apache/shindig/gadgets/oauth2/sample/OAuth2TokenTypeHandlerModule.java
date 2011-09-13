/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */

package org.apache.shindig.gadgets.oauth2.sample;

import org.apache.shindig.gadgets.oauth2.OAuth2TokenTypeHandler;

import com.google.inject.AbstractModule;

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public class OAuth2TokenTypeHandlerModule extends AbstractModule {

  @Override
  protected void configure() {
    this.bind(OAuth2TokenTypeHandler.class).to(BearerTokenHandler.class);
  }
}