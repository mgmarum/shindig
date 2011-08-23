/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/*global opensocial */

/**
 * @fileoverview ResponseItem containing information about a specific response
 * from the server.
 */


/**
 * @class
 * Represents a response that was generated
 * by processing a data request item on the server.
 *
 * @name opensocial.ResponseItem
 */


/**
 * Represents a response that was generated by processing a data request item
 * on the server.
 *
 * @private
 * @constructor
 * @deprecated since 1.0 see http://opensocial-resources.googlecode.com/svn/spec/1.0/Social-Gadget.xml#rfc.section.A.49.
 */
opensocial.ResponseItem = function(originalDataRequest, data,
    opt_errorCode, opt_errorMessage) {
  this.originalDataRequest_ = originalDataRequest;
  this.data_ = data;
  this.errorCode_ = opt_errorCode;
  this.errorMessage_ = opt_errorMessage;
};


/**
 * Returns true if there was an error in fetching this data from the server.
 *
 * @return {boolean} True if there was an error; otherwise, false.
 * @deprecated since 1.0 see http://opensocial-resources.googlecode.com/svn/spec/1.0/Social-Gadget.xml#rfc.section.A.49.1.5.
 */
opensocial.ResponseItem.prototype.hadError = function() {
  return !!this.errorCode_;
};


/**
 * @static
 * @class
 *
 * Error codes that a response item can return.
 *
 * @name opensocial.ResponseItem.Error
 * @deprecated since 1.0 see http://opensocial-resources.googlecode.com/svn/spec/1.0/Social-Gadget.xml#rfc.section.A.50.
 */
opensocial.ResponseItem.Error = {
  /**
   * This container does not support the request that was made.
   *
   * @member opensocial.ResponseItem.Error
   */
  NOT_IMPLEMENTED: 'notImplemented',

  /**
   * The gadget does not have access to the requested data.
   * To get access, use
   * <a href="opensocial.html#requestPermission">
   * opensocial.requestPermission()</a>.
   *
   * @member opensocial.ResponseItem.Error
   */
  UNAUTHORIZED: 'unauthorized',

  /**
   * The gadget can never have access to the requested data.
   *
   * @member opensocial.ResponseItem.Error
   */
  FORBIDDEN: 'forbidden',

  /**
   * The request was invalid. Example: 'max' was -1.
   *
   * @member opensocial.ResponseItem.Error
   */
  BAD_REQUEST: 'badRequest',

  /**
   * The request encountered an unexpected condition that
   * prevented it from fulfilling the request.
   *
   * @member opensocial.ResponseItem.Error
   */
  INTERNAL_ERROR: 'internalError',

  /**
   * The gadget exceeded a quota on the request. Example quotas include a
   * max number of calls per day, calls per user per day, calls within a
   * certain time period and so forth.
   *
   * @member opensocial.ResponseItem.Error
   */
  LIMIT_EXCEEDED: 'limitExceeded'
};


/**
 * If the request had an error, returns the error code.
 * The error code can be container-specific
 * or one of the values defined by
 * <a href="opensocial.ResponseItem.Error.html"><code>Error</code></a>.
 *
 * @return {string} The error code, or null if no error occurred.
 * @deprecated since 1.0 see http://opensocial-resources.googlecode.com/svn/spec/1.0/Social-Gadget.xml#rfc.section.A.49.1.2.
 */
opensocial.ResponseItem.prototype.getErrorCode = function() {
  return this.errorCode_;
};


/**
 * If the request had an error, returns the error message.
 *
 * @return {string} A human-readable description of the error that occurred;
 *    can be null, even if an error occurred.
 * @deprecated since 1.0 see http://opensocial-resources.googlecode.com/svn/spec/1.0/Social-Gadget.xml#rfc.section.A.49.1.3.
 */
opensocial.ResponseItem.prototype.getErrorMessage = function() {
  return this.errorMessage_;
};


/**
 * Returns the original data request.
 *
 * @return {opensocial.DataRequest} The data request used to fetch this data
 *    response.
 * @deprecated since 1.0 see http://opensocial-resources.googlecode.com/svn/spec/1.0/Social-Gadget.xml#rfc.section.A.49.1.4.
 */
opensocial.ResponseItem.prototype.getOriginalDataRequest = function() {
  return this.originalDataRequest_;
};


/**
 * Gets the response data.
 *
 * @return {Object} The requested value calculated by the server; the type of
 *    this value is defined by the type of request that was made.
 * @deprecated since 1.0 see http://opensocial-resources.googlecode.com/svn/spec/1.0/Social-Gadget.xml#rfc.section.A.49.1.1.
 */
opensocial.ResponseItem.prototype.getData = function() {
  return this.data_;
};
