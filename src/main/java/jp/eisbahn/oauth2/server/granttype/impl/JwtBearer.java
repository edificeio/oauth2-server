package jp.eisbahn.oauth2.server.granttype.impl;

import org.apache.commons.lang3.StringUtils;

import jp.eisbahn.oauth2.server.async.Handler;
import jp.eisbahn.oauth2.server.data.DataHandler;
import jp.eisbahn.oauth2.server.exceptions.OAuthError;
import jp.eisbahn.oauth2.server.exceptions.Try;
import jp.eisbahn.oauth2.server.models.AuthInfo;
import jp.eisbahn.oauth2.server.models.ClientCredential;
import jp.eisbahn.oauth2.server.models.Request;
import jp.eisbahn.oauth2.server.models.UserData;

public class JwtBearer extends AbstractGrantHandler {

    @Override
    public void handleRequest(DataHandler dataHandler, Handler<Try<OAuthError, GrantHandlerResult>> handler) {
        final Request request = dataHandler.getRequest();

        ClientCredential clientCredential = getClientCredentialFetcher().fetch(request);
        final String clientId = clientCredential.getClientId();

        try {
            final String assertion = getParameter(request, "assertion");
            final String scope = getParameter(request, "scope");

            dataHandler.getUserIdByAssertionJwt(clientId, assertion, new Handler<Try<OAuthError, UserData>>() {
                @Override
                public void handle(Try<OAuthError, UserData> tryUserId) {
                    try {
                        final UserData userData = tryUserId.get();
                        if (userData == null || StringUtils.isEmpty(userData.getId())) {
                            throw new OAuthError.InvalidGrant("");
                        }

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
                                                        new OAuthError.InvalidGrant("JWT is invalid.")));
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
