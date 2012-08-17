# Fernet

Fernet allows you to easily generate and verify **HMAC based authentication
tokens** for issuing API requests between remote servers. It also **encrypts**
data by default, so it can be used to transmit secure messages over the wire.

![Fernet](http://f.cl.ly/items/2d0P3d26271O3p2v253u/photo.JPG)

Fernet is usually served as a *digestif* after a meal but may also be served
with coffee and espresso or mixed into coffee and espresso drinks.

Fernet about it!

## Installation

Add this line to your application's Gemfile:

    gem 'fernet'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install fernet

## Usage

Both server and client must share a secret.

You want to encode some data in the token as well, for example, an email
address can be used to verify it on the other end.

```ruby
token = Fernet.generate(secret) do |generator|
  generator.data = { email: 'harold@heroku.com' }
end
```
On the server side, the receiver can use this token to verify whether it's
legit:

```ruby
verified = Fernet.verify(secret, token) do |verifier|
  verifier.data['email'] == 'harold@heroku.com'
end
```

The `verified` variable will be true if:

* The email encoded in the token data is `harold@heroku.com`
* The token was generated in the last 60 seconds
* The secret used to generate the token matches

Otherwise, `verified` will be false, and you should deny the request with an
HTTP 401, for example.

The `Fernet.verify` method can be awkward if extracting the plain text data is
required. For this case, a `verifier` can be requested that makes that
use case more pleasent:

```ruby
verifier = Fernet.verifier(secret, token)
if verifier.valid? # signature valid, TTL verified
  operate_on(verifier.data) # the original, decrypted data
end
```

The specs
([spec/fernet_spec.rb](https://github.com/hgmnz/fernet/blob/master/spec/fernet_spec.rb))
have more usage examples.

### Global configuration

It's possible to configure fernet via the `Configuration` class. Put this in an initializer:

```ruby
# default values shown here
Fernet::Configuration.run do |config|
  config.enforce_ttl = true
  config.ttl         = 60
  config.encrypt     = true
end
```

### Generating a secret

Generating appropriate secrets is beyond the scope of `Fernet`, but you should
generate it using `/dev/random` in a *nix. To generate a base64-encoded 256 bit
(32 byte) random sequence, try:

    dd if=/dev/urandom bs=32 count=1 2>/dev/null | openssl base64

### Attribution

This library was largely made possible by [Mr. Tom
Maher](http://twitter.com/#tmaher), who clearly articulated the mechanics
behind this process, and further found ways to make it
[more](https://github.com/hgmnz/fernet/commit/2bf0b4a66b49ef3fc92ef50708a2c8b401950fc2)
[secure](https://github.com/hgmnz/fernet/commit/051161d0afb0b41480734d84bc824bdbc7f9c563).

## License

Fernet is copyright (c) Harold Giménez and is released under the terms of the
MIT License found in the LICENSE file.
