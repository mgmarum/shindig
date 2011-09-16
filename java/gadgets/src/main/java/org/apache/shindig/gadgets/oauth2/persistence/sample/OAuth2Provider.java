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
package org.apache.shindig.gadgets.oauth2.persistence.sample;

import java.io.Serializable;

public class OAuth2Provider implements Serializable {
  /**
   * 
   */
  private static final long serialVersionUID = 1L;
  private String name;
  private String authorizationUrl;
  private String tokenUrl;
  private String clientAuthenticationType;

  public String getClientAuthenticationType() {
    return this.clientAuthenticationType;
  }

  public void setClientAuthenticationType(final String clientAuthenticationType) {
    this.clientAuthenticationType = clientAuthenticationType;
  }

  public String getName() {
    return this.name;
  }

  public void setName(final String name) {
    this.name = name;
  }

  public String getAuthorizationUrl() {
    return this.authorizationUrl;
  }

  public void setAuthorizationUrl(final String authorizationUrl) {
    this.authorizationUrl = authorizationUrl;
  }

  public String getTokenUrl() {
    return this.tokenUrl;
  }

  public void setTokenUrl(final String tokenUrl) {
    this.tokenUrl = tokenUrl;
  }

  @Override
  public boolean equals(final Object obj) {
    final boolean ret = false;
    if (OAuth2Provider.class.isInstance(obj)) {
      final OAuth2Provider otherProvider = (OAuth2Provider) obj;
      return this.name.equals(otherProvider.getName());
    }

    return ret;
  }

  @Override
  public int hashCode() {
    if (this.name != null) {
      return this.name.hashCode();
    }

    return 0;
  }

  @Override
  public String toString() {
    return "org.apache.shindig.gadgets.oauth2.persistence.sample.OAuth2Provider: name = "
        + this.name + " , authorizationUrl = " + this.authorizationUrl + " , tokenUrl = "
        + this.tokenUrl + " , clientAuthenticationType = " + this.clientAuthenticationType;
  }
}
