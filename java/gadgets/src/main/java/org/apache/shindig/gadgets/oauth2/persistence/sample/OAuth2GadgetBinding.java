package org.apache.shindig.gadgets.oauth2.persistence.sample;

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
