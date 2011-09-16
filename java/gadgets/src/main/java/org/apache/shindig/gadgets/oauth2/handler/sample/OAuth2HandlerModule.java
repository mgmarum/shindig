/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with this
 * work for additional information regarding copyright ownership. The ASF
 * licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
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

/**
 * Injects the default handlers.
 * 
 */
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