# Fernet

Fernet allows you to easily generate and verify HMAC based authentication tokens for issuing API requests between remote servers.

![Fernet](http://f.cl.ly/items/2d0P3d26271O3p2v253u/photo.JPG)

Fernet is usually served as a *digestif* after a meal but may also be served with coffee and espresso or mixed into coffee and espresso drinks.

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

You want to encode some data in the token as well, for example, an email address can be used to verify it on the other end.

```ruby
token = Fernet.generate(secret) do |generator|
  generator.data = { email: 'harold@heroku.com' }
end
```
On the server side, the receiver can use this token to verify whether it's legit:

```ruby
verified = Fernet.verify(secret, token) do |verifier|
  verifier.data['email'] == 'harold@heroku.com'
end
```

The `verified` variable will be true if:

* The email encoded in the token data is `harold@heroku.com`
* The token was generated in the last 60 seconds
* The secret used to generate the token matches

Otherwise, `verified` will be false, and you should deny the request with an HTTP 401, for example.

The specs ([spec/fernet_spec.rb](https://github.com/hgimenez/fernet/blob/master/spec/fernet_spec.rb)) have more usage examples.

## License

Fernet is copyright (c) Harold Giménez and is released under the terms of the
MIT License found in the LICENSE file.
