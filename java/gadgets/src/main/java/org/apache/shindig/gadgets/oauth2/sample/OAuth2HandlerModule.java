/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */

package org.apache.shindig.gadgets.oauth2.sample;

import java.util.List;

import org.apache.shindig.gadgets.oauth2.OAuth2AuthorizationResponseHandler;
import org.apache.shindig.gadgets.oauth2.OAuth2ClientAuthenticationHandler;
import org.apache.shindig.gadgets.oauth2.OAuth2GrantTypeHandler;
import org.apache.shindig.gadgets.oauth2.OAuth2TokenTypeHandler;

import com.google.common.collect.ImmutableList;
import com.google.inject.AbstractModule;
import com.google.inject.Provides;
import com.google.inject.Singleton;

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public class OAuth2HandlerModule extends AbstractModule {

  @Override
  protected void configure() {
  }

  @Provides
  @Singleton
  List<OAuth2TokenTypeHandler> provideTokenHandlers(final BearerTokenHandler bearerTokenHandler) {
    return ImmutableList.of((OAuth2TokenTypeHandler) bearerTokenHandler);
  }
  
  @Provides
  @Singleton
  List<OAuth2GrantTypeHandler> provideGrantTypeHandlers(final ClientCredentialsGrantTypeHandler clientCredentialsGrantTypeHandler, final CodeGrantTypeHandler codeGrantTypeHandler) {
    return ImmutableList.of((OAuth2GrantTypeHandler) clientCredentialsGrantTypeHandler, (OAuth2GrantTypeHandler) codeGrantTypeHandler);
  }
  
  @Provides
  @Singleton
  List<OAuth2ClientAuthenticationHandler> provideClientAuthenticationHandlers(final BasicAuthenticationHandler basicAuthenticationHandler) {
    return ImmutableList.of((OAuth2ClientAuthenticationHandler) basicAuthenticationHandler);
  }
  
  @Provides
  @Singleton
  List<OAuth2AuthorizationResponseHandler> provideAuthorizationResponseHandlers(final CodeAuthorizationResponseHandler codeAuthorizationResponseHandler) {
    return ImmutableList.of((OAuth2AuthorizationResponseHandler) codeAuthorizationResponseHandler);
  }
}