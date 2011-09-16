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
package org.apache.shindig.gadgets.oauth2;

import java.io.Serializable;

import org.apache.shindig.gadgets.oauth2.handler.ClientAuthenticationHandler;

/**
 * OAuth2 related data accessor.
 * 
 * Every {@link OAuth2Request} will create an accessor and store it in the
 * OAuth2Store while the request is being issued. It will be removed when the
 * request is done (success or failure.)
 * 
 * OAuth2Accessor implementations should be {@link Serializable} to facilitate
 * cluster storage and caching across the various phases of OAuth 2.0 flows.
 */

public interface OAuth2Accessor extends Serializable {
  /**
   * 
   * Enumeration of possible accessor types
   * 
   */
  public enum Type {
    CONFIDENTIAL, PUBLIC, UNKNOWN
  }

  /**
   * 
   * @return the access {@link OAuth2Token} or <code>null</code>
   */
  public OAuth2Token getAccessToken();

  /**
   * 
   * @return the authorization endpoint for this accessor.
   */
  public String getAuthorizationUrl();

  /**
   * see {@link ClientAuthenticationHandler}
   * @return the type of client authentication the service provider expects
   */
  public String getClientAuthenticationType();

  /**
   * 
   * @return the "client_id" for this accessor
   */
  public String getClientId();

  /**
   * 
   * @return the "client_secret" for this accessor
   */
  public String getClientSecret();

  /**
   * 
   * @return the URI of the gadget issuing the request
   */
  public String getGadgetUri();

  /**
   * 
   * @return grant_type of this client, e.g. "code" or "client_credentials"
   */
  public String getGrantType();

  /**
   * 
   * @return redirect_uri of the client for this accessor
   */
  public String getRedirectUri();

  /**
   * 
   * @return the refresh {@link OAuth2Token} or <code>null</code>
   */
  public OAuth2Token getRefreshToken();

  /**
   * if the gadget request or gadget spec specifies a scope it will be set here
   * 
   * @return scope of the request, or "" if none was specified
   */
  public String getScope();

  /**
   * 
   * @return the service name from the gadget spec, defaults to ""
   */
  public String getServiceName();

  /**
   * 
   * @return the state to include on authorization requests
   */
  public String getState();

  
  /**
   * 
   * @return the token endpoint for this accessor.
   */
  public String getTokenUrl();

  /**
   * 
   * @return the {@link Type} of client for this accessor
   */
  public Type getType();

  /**
   * 
   * @return of the page viewer
   */
  public String getUser();

  /**
   * 
   * @return <code>true</code> if the gadget's <ModulePrefs> can override accessor settings
   */
  public boolean isAllowModuleOverrides();

  /**
   * updates the access token for the request (does not add it to {@link OAuth2Store})
   * @param accessToken
   */
  public void setAccessToken(OAuth2Token accessToken);

  /**
   * updates the authorization endpoint url
   * 
   * @param authorizationUrl
   */
  public void setAuthorizationUrl(String authorizationUrl);

  /**
   * updates the refresh token for the request (does not add it to {@link OAuth2Store})
   * @param accessToken
   */
  public void setRefreshToken(OAuth2Token refreshToken);

  /**
   * updates the token endpoint url
   * 
   * @param tokenUrl
   */
  public void setTokenUrl(String tokenUrl);
}
