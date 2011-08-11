/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.apache.shindig.social.core.oauth;

import org.apache.shindig.auth.AnonymousAuthenticationHandler;
import org.apache.shindig.auth.AuthenticationHandler;
import org.apache.shindig.auth.UrlParameterAuthenticationHandler;
import org.apache.shindig.social.core.oauth2.OAuth2AuthenticationHandler;

import java.util.List;

import com.google.common.collect.Lists;
import com.google.inject.Inject;
import com.google.inject.Provider;

/**
 * Guice provider of an ordered list of Auntentication Probviders
 */
public class AuthenticationHandlerProvider implements Provider<List<AuthenticationHandler>> {
  protected List<AuthenticationHandler> handlers;

  @Inject
  public AuthenticationHandlerProvider(UrlParameterAuthenticationHandler urlParam,
      OAuthAuthenticationHandler threeLeggedOAuth, OAuth2AuthenticationHandler oauth2Handler,
      AnonymousAuthenticationHandler anonymous) {
    handlers = Lists.newArrayList(urlParam, threeLeggedOAuth, oauth2Handler, anonymous);
  }

  public List<AuthenticationHandler> get() {
    return handlers;
  }
}
