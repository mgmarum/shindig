/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */

package org.apache.shindig.gadgets.oauth2.handler.sample;

import java.util.List;

import org.apache.shindig.gadgets.oauth2.handler.AuthorizationEndpointResponseHandler;
import org.apache.shindig.gadgets.oauth2.handler.ClientAuthenticationHandler;
import org.apache.shindig.gadgets.oauth2.handler.GrantRequestHandler;
import org.apache.shindig.gadgets.oauth2.handler.ResourceRequestHandler;
import org.apache.shindig.gadgets.oauth2.handler.TokenEndpointResponseHandler;

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
  List<ResourceRequestHandler> provideTokenHandlers(final BearerTokenHandler bearerTokenHandler) {
    return ImmutableList.of((ResourceRequestHandler) bearerTokenHandler);
  }

  @Provides
  @Singleton
  List<GrantRequestHandler> provideGrantRequestHandlers(
      final ClientCredentialsGrantTypeHandler clientCredentialsGrantTypeHandler,
      final CodeGrantTypeHandler codeGrantTypeHandler) {
    return ImmutableList.of(clientCredentialsGrantTypeHandler, codeGrantTypeHandler);
  }

  @Provides
  @Singleton
  List<ClientAuthenticationHandler> provideClientAuthenticationHandlers(
      final BasicAuthenticationHandler basicAuthenticationHandler) {
    return ImmutableList.of((ClientAuthenticationHandler) basicAuthenticationHandler);
  }

  @Provides
  @Singleton
  List<AuthorizationEndpointResponseHandler> provideAuthorizationEndpointResponseHandlers(
      final CodeAuthorizationResponseHandler codeAuthorizationResponseHandler,
      final TokenAuthorizationResponseHandler tokenAuthorizationResponseHandler) {
    return ImmutableList
        .of((AuthorizationEndpointResponseHandler) codeAuthorizationResponseHandler);
  }

  @Provides
  @Singleton
  List<TokenEndpointResponseHandler> provideTokenEndpointResponseHandlers(
      final TokenAuthorizationResponseHandler tokenAuthorizationResponseHandler) {
    return ImmutableList.of((TokenEndpointResponseHandler) tokenAuthorizationResponseHandler);
  }
}