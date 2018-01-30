# Fernet

[![Build Status](https://secure.travis-ci.org/fernet/fernet-rb.png)](http://travis-ci.org/fernet/fernet-rb)
[![Code Climate](https://codeclimate.com/github/fernet/fernet-rb.png)](https://codeclimate.com/github/fernet/fernet-rb)

Fernet allows you to easily generate and verify **HMAC based authentication
tokens** for issuing API requests between remote servers. It also **encrypts**
the message so it can be used to transmit secure data over the wire.

![Fernet](http://f.cl.ly/items/2d0P3d26271O3p2v253u/photo.JPG)

Fernet is usually served as a *digestif* after a meal but may also be served
with coffee and espresso or mixed into coffee and espresso drinks.

Fernet about it!

## Installation

Fernet is distributed as [a rubygem](https://rubygems.org/gems/fernet), so
either add `gem 'fernet'` to your application's Gemfile or install it yourself
by running `gem install fernet`.

## Usage

Both server and client must share a secret.

You want to encode some data in the token as well, for example, an email
address can be used to verify it on the other end.

```ruby
token = Fernet.generate(secret, 'harold@heroku.com')
```

On the server side, the receiver can use this token to verify whether it's
legit:

```ruby
verifier = Fernet.verifier(secret, token)
if verifier.valid?
  operate_on(verifier.message) # the original, decrypted message
end
```

The verifier is valid if:

* The token was generated in the last 60 seconds (or some configurable TTL)
* The secret used to generate the token matches

Otherwise, `verified` will be false, and you should deny the request with an
HTTP 401, for example.

Additional secrets can be provided, and the verifier will try each of these in
turn.

The specs
([spec/fernet_spec.rb](https://github.com/hgmnz/fernet/blob/master/spec/fernet_spec.rb))
have more usage examples.

### Global configuration

It's possible to configure fernet via the `Configuration` class. To do so, put
this in an initializer:

```ruby
# default values shown here
Fernet::Configuration.run do |config|
  config.enforce_ttl = true
  config.ttl         = 60
end
```

### Generating a secret

Generating appropriate secrets is beyond the scope of `Fernet`, but you should
generate it using `/dev/random` in a *nix. To generate a base64-encoded 256 bit
(32 byte) random sequence, try:

    dd if=/dev/urandom bs=32 count=1 2>/dev/null | openssl base64

### Ruby Compatibility

Fernet is compatible with Ruby 1.9 and above. It is tested on the rubies
available on this [Travis CI configuration
file](https://github.com/hgmnz/fernet/blob/master/.travis.yml)

### Attribution

This library was largely made possible by [Mr. Tom
Maher](https://twitter.com/tmaher), who clearly articulated the mechanics
behind this process, and further found ways to make it
[more](https://github.com/hgmnz/fernet/commit/2bf0b4a66b49ef3fc92ef50708a2c8b401950fc2)
[secure](https://github.com/hgmnz/fernet/commit/051161d0afb0b41480734d84bc824bdbc7f9c563).

Similarly, [Mr. Keith Rarick](https://twitter.com/krarick) who implemented a [Go
version](https://github.com/kr/fernet) and put together the [Fernet
spec](https://github.com/kr/fernet-spec) which is used by this project to
verify interoparability.

### Contributing

Contributions are welcome via github pull requests.

To run the test suite:

* Clone the project
* Init submodules with `git submodule init && git submodule update`
* Run the suite: `bundle exec rspec spec`

Thanks to all [contributors](https://github.com/hgmnz/fernet/contributors).

### Security disclosures

If you find a security issue with Fernet, please report it by emailing
the fernet security list: fernet-secure@googlegroups.com

## License

Fernet is copyright (c) Harold Giménez and is released under the terms of the
MIT License found in the LICENSE file.
