package jp.eisbahn.oauth2.server.data;

import jp.eisbahn.oauth2.server.async.Handler;
import jp.eisbahn.oauth2.server.models.AccessToken;
import jp.eisbahn.oauth2.server.models.AuthInfo;
import jp.eisbahn.oauth2.server.models.Request;

public abstract class DataHandlerSync extends DataHandler {

	public DataHandlerSync(Request request) {
		super(request);
	}

	@Override
	public void validateClient(String clientId, String clientSecret,
			String grantType, Handler<Boolean> handler) {
		handler.handle(validateClient(clientId, clientSecret, grantType));
	}

	public abstract boolean validateClient(String clientId, String clientSecret,
			String grantType);

	@Override
	public void getUserId(String username, String password,
			Handler<String> handler) {
		// TODO Auto-generated method stub

	}

	@Override
	public void createOrUpdateAuthInfo(String clientId, String userId,
			String scope, Handler<AuthInfo> handler) {
		// TODO Auto-generated method stub

	}

	@Override
	public void createOrUpdateAccessToken(AuthInfo authInfo,
			Handler<AccessToken> handler) {
		// TODO Auto-generated method stub

	}

	@Override
	public void getAuthInfoByCode(String code, Handler<AuthInfo> handler) {
		// TODO Auto-generated method stub

	}

	@Override
	public void getAuthInfoByRefreshToken(String refreshToken,
			Handler<AuthInfo> handler) {
		// TODO Auto-generated method stub

	}

	@Override
	public void getClientUserId(String clientId, String clientSecret,
			Handler<String> handler) {
		// TODO Auto-generated method stub

	}

	@Override
	public void validateClientById(String clientId, Handler<Boolean> handler) {
		// TODO Auto-generated method stub

	}

	@Override
	public void validateUserById(String userId, Handler<Boolean> handler) {
		// TODO Auto-generated method stub

	}

	@Override
	public void getAccessToken(String token, Handler<AccessToken> handler) {
		// TODO Auto-generated method stub

	}

	@Override
	public void getAuthInfoById(String id, Handler<AuthInfo> handler) {
		// TODO Auto-generated method stub

	}

}
