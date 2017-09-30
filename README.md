# cyrus-sasl-xoauth2

This is a plugin implementation of [XOAUTH2](https://developers.google.com/gmail/xoauth2_protocol).

FYI: if you are forced to use XOAUTH2-enabled SMTP / IMAP servers by your employer and want to keep using your favorite \*nix MUA locally, the following detailed document should help a lot: http://mmogilvi.users.sourceforge.net/software/oauthbearer.html (DISCLAIMER: in contrast to the document's author, I'd rather read and write emails on my browser a lot.  I haven't tested it personally)

## Building and installation

```
./autogen.sh
./configure
sudo make install
```

## Server-side configuration

### auxprops

* `oauth2BearerTokens`

  Stores the token values for the specified authentication ID.

### SASL2 settings

* `xoauth2_scope`

  The name of the authorization scope that will appear in the error response.


## Example: Postfix server (smtpd) / client (smtp) authentication configuration

* `main.cf`:

  ```
  # ... OTHER SETTINGS GO HERE ...
  
  # SERVER
  smtpd_sasl_auth_enable = yes
  smtpd_sasl_path = smtpd
  smtpd_relay_restrictions = permit_sasl_authenticated, reject
  
  # CLIENT
  relayhost = [smtp.gmail.com]:587
  smtp_sasl_auth_enable = yes
  smtp_sasl_password_maps = hash:/etc/postfix/saslpasswd
  smtp_sasl_mechanism_filter = xoauth2
  smtp_sasl_security_options =
  smtp_tls_security_level = may
  smtp_tls_policy_maps = hash:/etc/postfix/tls_policy

  ```

* `/etc/postfix/saslpasswd`:

  ```
  [smtp.gmail.com]:587    YOUR-ACCOUNT@gmail.com:OAUTH2-TOKEN-RETRIEVED-BY-GMAIL-OAUTH2-TOOLS
  ```

  * `/etc/postfix/saslpasswd.db` needs to be generated with `postmap`:

    ```
    # postmap /etc/postfix/saslpasswd
    ```

  * Gmail OAuth2 Tools can be found [here](https://github.com/google/gmail-oauth2-tools).

* `/etc/postfix/tls_policy`:

  ```
  [smtp.gmail.com]:587    encrypt
  ```
  
  * `/etc/postfix/tls_policy.db` needs to be generated with `postmap`:

    ```
    # postmap /etc/postfix/tls_policy
    ```

* `${sasl_plugin_dir}/smtpd.conf`:

    ```
    log_level: DEBUG
    sql_engine: sqlite3
    sql_database: /etc/sasldb2.sqlite3
    sql_select: SELECT props.value FROM users JOIN props ON users.id=props.user_id WHERE users.name='%u' AND users.realm='%r' AND props.name='%p'
    xoauth2_scope: https://mail.example.com/
    auxprop_plugin: sql
    mech_list: xoauth2
    ```

* `/etc/sasldb2.sqlite3`:

  Generated from the following DDL and SQL statements:

  ```
  PRAGMA foreign_keys=OFF;
  BEGIN TRANSACTION;
  CREATE TABLE users (id INTEGER PRIMARY KEY, name VARCHAR, password VARCHAR, realm VARCHAR);
  INSERT INTO "users" VALUES(1,'test','test','example.com');
  CREATE TABLE props (id INTEGER PRIMARY KEY, user_id INTEGER, name VARCHAR, value VARCHAR, FOREIGN KEY (user_id) REFERENCES users (id));
  INSERT INTO "props" VALUES(1,1,'userPassword','*');
  INSERT INTO "props" VALUES(2,1,'oauth2BearerTokens','token');
  COMMIT;
  ```
