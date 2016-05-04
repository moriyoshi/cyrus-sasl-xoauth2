# cyrus-sasl-xoauth2

This is a plugin implementation of [XOAUTH2](https://developers.google.com/gmail/xoauth2_protocol).

## Build and installation

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

