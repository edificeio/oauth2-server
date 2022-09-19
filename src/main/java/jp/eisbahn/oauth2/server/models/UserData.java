package jp.eisbahn.oauth2.server.models;

public class UserData {

    private final String id;
    private final String activationCode;
    private final String login;
    private final String email;
    private final String mobile;
    private final String source;

    public UserData(String id) {
        this(id, null, null, null, null, null);
    }

    public UserData(String id, String activationCode, String login, String email, String mobile, String source) {
        this.id = id;
        this.activationCode = activationCode;
        this.login = login;
        this.email = email;
        this.mobile = mobile;
        this.source = source;
    }

    public String getId() {
        return id;
    }

    public String getActivationCode() {
        return activationCode;
    }

    public String getLogin() {
        return login;
    }

    public String getEmail() {
        return email;
    }

    public String getMobile() {
        return mobile;
    }

    public String getSource() {
        return source;
    }

}
