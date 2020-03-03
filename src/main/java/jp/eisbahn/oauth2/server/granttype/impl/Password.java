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

package jp.eisbahn.oauth2.server.granttype.impl;

import jp.eisbahn.oauth2.server.async.Handler;
import jp.eisbahn.oauth2.server.exceptions.Try;
import jp.eisbahn.oauth2.server.exceptions.OAuthError.AccessDenied;

import org.apache.commons.lang3.StringUtils;

import jp.eisbahn.oauth2.server.data.DataHandler;
import jp.eisbahn.oauth2.server.exceptions.OAuthError;
import jp.eisbahn.oauth2.server.models.AuthInfo;
import jp.eisbahn.oauth2.server.models.ClientCredential;
import jp.eisbahn.oauth2.server.models.Request;

/**
 * This class is an implementation for processing the Resource Owner Password
 * Credentials Grant flow of OAuth2.0.
 *
 * @author Yoichiro Tanaka
 *
 */
public class Password extends AbstractGrantHandler {

	/*
	 * (non-Javadoc)
	 * @see jp.eisbahn.oauth2.server.granttype.GrantHandler#handleRequest(jp.eisbahn.oauth2.server.data.DataHandler)
	 */
	@Override
	public void handleRequest(final DataHandler dataHandler, final Handler<Try<OAuthError, GrantHandlerResult>> handler) {
		final Request request = dataHandler.getRequest();

		ClientCredential clientCredential = getClientCredentialFetcher().fetch(request);
		final String clientId = clientCredential.getClientId();

		try {
			String username = getParameter(request, "username");
			String password = getParameter(request, "password");

			dataHandler.getUserId(username, password, new Handler<Try<AccessDenied, String>>() {
				@Override
				public void handle(Try<AccessDenied, String> tryUserId) {
					try {
						final String userId = tryUserId.get();
						if (StringUtils.isEmpty(userId)) {
							throw new OAuthError.InvalidGrant("");
						}
						String scope = request.getParameter("scope");

						dataHandler.createOrUpdateAuthInfo(clientId, userId, scope, new Handler<AuthInfo>() {
							@Override
							public void handle(AuthInfo authInfo) {
								try {
									if (authInfo == null) {
										throw new OAuthError.InvalidGrant("");
									}
									if (!authInfo.getClientId().equals(clientId)) {
										throw new OAuthError.InvalidClient("");
									}

									issueAccessToken(dataHandler, authInfo, new Handler<GrantHandlerResult>() {

										@Override
										public void handle(GrantHandlerResult result) {
											if (result != null) {
												handler.handle(new Try<OAuthError, GrantHandlerResult>(result));
											} else {
												handler.handle(new Try<OAuthError, GrantHandlerResult>(
														new OAuthError.InvalidGrant("Credential is invalid.")));
											}
										}
									});
								} catch (OAuthError ex) {
									handler.handle(new Try<OAuthError, GrantHandlerResult>(ex));
								}
							}
						});
					} catch (OAuthError ex) {
						handler.handle(new Try<OAuthError, GrantHandlerResult>(ex));
					}
				}
			});
		} catch (OAuthError ex) {
			handler.handle(new Try<OAuthError, GrantHandlerResult>(ex));
		}
	}

}
