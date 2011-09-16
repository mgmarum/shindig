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

/**
 * Binds a gadget to a client.
 * 
 */
public class OAuth2GadgetBinding {
  private final String gadgetUri;
  private final String gadgetServiceName;
  private final String clientName;
  private final boolean allowOverride;

  public OAuth2GadgetBinding(final String gadgetUri, final String gadgetServiceName,
      final String clientName, final boolean allowOverride) {
    this.gadgetUri = gadgetUri;
    this.gadgetServiceName = gadgetServiceName;
    this.clientName = clientName;
    this.allowOverride = allowOverride;
  }

  public boolean isAllowOverride() {
    return this.allowOverride;
  }

  public String getGadgetUri() {
    return this.gadgetUri;
  }

  public String getGadgetServiceName() {
    return this.gadgetServiceName;
  }

  public String getClientName() {
    return this.clientName;
  }

  @Override
  public boolean equals(final Object obj) {
    if (OAuth2GadgetBinding.class.isInstance(obj)) {
      final OAuth2GadgetBinding otherBinding = (OAuth2GadgetBinding) obj;
      return ((this.gadgetUri.equals(otherBinding.getGadgetUri())) && (this.gadgetServiceName
          .equals(otherBinding.getGadgetServiceName())));
    }

    return false;
  }

  @Override
  public int hashCode() {
    if ((this.gadgetUri != null) && (this.gadgetServiceName != null)) {
      return (this.gadgetUri + ":" + this.gadgetServiceName).hashCode();
    }

    return 0;
  }

  @Override
  public String toString() {
    return "org.apache.shindig.gadgets.oauth2.persistence.sample.OAuth2GadgetBinding: gadgetUri = "
        + this.gadgetUri + " , gadgetServiceName = " + this.gadgetServiceName
        + " , allowOverride = " + this.allowOverride;
  }
}
