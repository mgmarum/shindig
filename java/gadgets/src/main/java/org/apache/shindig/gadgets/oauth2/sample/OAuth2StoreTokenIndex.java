/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2.sample;

import org.apache.shindig.gadgets.oauth.BasicOAuthStoreTokenIndex;

/**
 * Simple class representing OAuth2 token index
 */

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public class OAuth2StoreTokenIndex extends BasicOAuthStoreTokenIndex {
  private static final String OAUTH2_PREFIX = "OAUTH2_";

  @Override
  public String toString() {
    return "OAuth2StoreTokenIndex: gadgetUri = " + super.getGadgetUri() + " , moduleId = "
        + super.getModuleId() + " , serviceName = " + super.getServiceName() + " , tokenName = "
        + super.getTokenName() + " , userId = " + super.getUserId() + " , hashCode = "
        + super.hashCode();
  }

  @Override
  public void setGadgetUri(final String gadgetUri) {
    String setTo = gadgetUri;
    if ((gadgetUri != null) && (gadgetUri.length() > 0)) {
      if (!gadgetUri.startsWith(OAuth2StoreTokenIndex.OAUTH2_PREFIX)) {
        setTo = OAuth2StoreTokenIndex.OAUTH2_PREFIX + gadgetUri;
      }
    }

    super.setGadgetUri(setTo);
  }

  @Override
  public void setServiceName(final String serviceName) {
    String setTo = serviceName;
    if ((serviceName != null) && (serviceName.length() > 0)) {
      if (!serviceName.startsWith(OAuth2StoreTokenIndex.OAUTH2_PREFIX)) {
        setTo = OAuth2StoreTokenIndex.OAUTH2_PREFIX + serviceName;
      }
    }

    super.setServiceName(setTo);
  }

  @Override
  public void setTokenName(final String tokenName) {
    String setTo = tokenName;
    if ((tokenName != null) && (tokenName.length() > 0)) {
      if (!tokenName.startsWith(OAuth2StoreTokenIndex.OAUTH2_PREFIX)) {
        setTo = OAuth2StoreTokenIndex.OAUTH2_PREFIX + tokenName;
      }
    }

    super.setTokenName(setTo);
  }

  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof OAuth2StoreTokenIndex)) {
      return false;
    }
    final OAuth2StoreTokenIndex other = (OAuth2StoreTokenIndex) obj;
    if (super.getGadgetUri() == null) {
      if (other.getGadgetUri() != null) {
        return false;
      }
    } else if (!super.getGadgetUri().equals(other.getGadgetUri())) {
      return false;
    }
    if (super.getModuleId() != other.getModuleId()) {
      return false;
    }
    if (super.getServiceName() == null) {
      if (other.getServiceName() != null) {
        return false;
      }
    } else if (!super.getServiceName().equals(other.getServiceName())) {
      return false;
    }
    if (super.getTokenName() == null) {
      if (other.getTokenName() != null) {
        return false;
      }
    } else if (!super.getTokenName().equals(other.getTokenName())) {
      return false;
    }
    if (super.getUserId() == null) {
      if (other.getUserId() != null) {
        return false;
      }
    } else if (!super.getUserId().equals(other.getUserId())) {
      return false;
    }
    return true;
  }
}
