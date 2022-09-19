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

import org.apache.commons.lang3.StringUtils;

import jp.eisbahn.oauth2.server.data.DataHandler;
import jp.eisbahn.oauth2.server.exceptions.OAuthError;
import jp.eisbahn.oauth2.server.models.AuthInfo;
import jp.eisbahn.oauth2.server.models.ClientCredential;
import jp.eisbahn.oauth2.server.models.Request;
import jp.eisbahn.oauth2.server.models.UserData;

/**
 * This class is an implementation for processing the OAuth-Saml
 * Credentials Grant flow of OAuth2.0.
 *
 * @author Damien BOISSIN
 *
 */
public class Saml2 extends AbstractGrantHandler {

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
			final String assertion = getParameter(request, "assertion");

			dataHandler.getUserIdByAssertion(assertion, new Handler<Try<OAuthError, UserData>>() {
				@Override
				public void handle(Try<OAuthError, UserData> tryUserId) {
					try {
						final UserData userData = tryUserId.get();
						if (userData == null || StringUtils.isEmpty(userData.getId())) {
							throw new OAuthError.InvalidGrant("");
						}
						String scope = request.getParameter("scope");

						dataHandler.createOrUpdateAuthInfo(clientId, userData.getId(), scope, new Handler<AuthInfo>() {
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
												result.setUserData(userData);
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
