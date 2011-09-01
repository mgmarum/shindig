/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2.sample;

import org.apache.shindig.gadgets.oauth.BasicOAuthStoreConsumerIndex;

/**
 * Index into the OAuth2 token store
 */

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public class OAuth2StoreConsumerIndex extends BasicOAuthStoreConsumerIndex {

  private static final String OAUTH2_PREFIX = "OAUTH2_";

  @Override
  public String toString() {
    return "OAuth2StoreConsumerIndex: gadgetUri = " + super.getGadgetUri() + " , serviceName = "
        + super.getServiceName() + " , hashCode = " + super.hashCode();
  }

  @Override
  public void setGadgetUri(final String gadgetUri) {
    String setTo = gadgetUri;
    if ((gadgetUri != null) && (gadgetUri.length() > 0)) {
      if (!gadgetUri.startsWith(OAuth2StoreConsumerIndex.OAUTH2_PREFIX)) {
        setTo = OAuth2StoreConsumerIndex.OAUTH2_PREFIX + gadgetUri;
      }
    }

    super.setGadgetUri(setTo);
  }

  @Override
  public void setServiceName(final String serviceName) {
    String setTo = serviceName;
    if ((serviceName != null) && (serviceName.length() > 0)) {
      if (!serviceName.startsWith(OAuth2StoreConsumerIndex.OAUTH2_PREFIX)) {
        setTo = OAuth2StoreConsumerIndex.OAUTH2_PREFIX + serviceName;
      }
    }

    super.setServiceName(setTo);
  }

  @Override
  public boolean equals(final Object obj) {
    if (obj == this) {
      return true;
    }
    if (!(obj instanceof OAuth2StoreConsumerIndex)) {
      return false;
    }
    final OAuth2StoreConsumerIndex other = (OAuth2StoreConsumerIndex) obj;
    if (super.getGadgetUri() == null) {
      if (other.getGadgetUri() != null) {
        return false;
      }
    } else if (!super.getGadgetUri().equals(other.getGadgetUri())) {
      return false;
    }
    if (super.getServiceName() == null) {
      if (other.getServiceName() != null) {
        return false;
      }
    } else if (!super.getServiceName().equals(other.getServiceName())) {
      return false;
    }
    return true;
  }
}
