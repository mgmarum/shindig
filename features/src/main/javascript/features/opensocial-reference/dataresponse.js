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
 * @fileoverview DataResponse containing information about
 * friends, contacts, profile, app data, and activities.
 *
 * Whenever a dataRequest is sent to the server it will return a dataResponse
 * object. Values from the server will be mapped to the requested keys specified
 * in the dataRequest.
 */


/**
 * @class
 * This object contains the requested server data mapped to the requested keys.
 *
 * <p>
 * <b>See also:</b>
 * <a href="opensocial.DataRequest.html">DataRequest</a>
 * </p>
 *
 * @name opensocial.DataResponse
 */

/**
 * Construct the data response.
 * This object contains the requested server data mapped to the requested keys.
 *
 * @param {Object.<string, ResponseItem>} responseItems Key/value map of data
 *    response information.
 * @param {boolean=} opt_globalError Optional field indicating whether there were
 *    any errors generating this data response.
 * @param {string=} opt_errorMessage
 *
 * @private
 * @constructor
 * @deprecated since 1.0 see http://opensocial-resources.googlecode.com/svn/spec/1.0/Social-Gadget.xml#rfc.section.A.20.
 */
opensocial.DataResponse = function(responseItems, opt_globalError,
    opt_errorMessage) {
  this.responseItems_ = responseItems;
  this.globalError_ = opt_globalError;
  this.errorMessage_ = opt_errorMessage;
};


/**
 * Returns true if there was an error in fetching this data from the server.
 *
 * @return {boolean} True if there was an error; otherwise, false.
 * @member opensocial.DataResponse
 * @deprecated since 1.0 see http://opensocial-resources.googlecode.com/svn/spec/1.0/Social-Gadget.xml#rfc.section.A.20.1.3.
 */
opensocial.DataResponse.prototype.hadError = function() {
  return !!this.globalError_;
};


/**
 * If the entire request had a batch level error, returns the error message.
 *
 * @return {string} A human-readable description of the error that occurred.
 * @deprecated since 1.0 see http://opensocial-resources.googlecode.com/svn/spec/1.0/Social-Gadget.xml#rfc.section.A.20.1.2.
 */
opensocial.DataResponse.prototype.getErrorMessage = function() {
  return this.errorMessage_;
};


/**
 * Gets the ResponseItem for the requested field.
 *
 * @return {opensocial.ResponseItem} The requested
 *    <a href="opensocial.ResponseItem.html">response</a> calculated by the
 *    server.
 * @member opensocial.DataResponse
 * @deprecated since 1.0 see http://opensocial-resources.googlecode.com/svn/spec/1.0/Social-Gadget.xml#rfc.section.A.20.1.1.
 */
opensocial.DataResponse.prototype.get = function(key) {
  return this.responseItems_[key];
};
