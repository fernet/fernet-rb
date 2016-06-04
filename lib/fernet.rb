require 'fernet/errors'
require 'fernet/version'
require 'fernet/bit_packing'
require 'fernet/encryption'
require 'fernet/token'
require 'fernet/generator'
require 'fernet/verifier'
require 'fernet/secret'
require 'fernet/configuration'

Fernet::Configuration.run

module Fernet
  # Determine AES key bits from base64-encoded secret length
  KEYBITS_SELECT = { 44 => 128, 64 => 192, 88 => 256 }.freeze

  # Public: generates a fernet token
  #
  # secret   - a base64 encoded 32, 48 or 64 byte string
  # message  - the message being secured in plain text
  #
  # Examples
  #
  #   secret = ...
  #   token = Fernet.generate(secret, 'my secrets')
  #
  # Returns the fernet token as a string
  def self.generate(secret, message = '', opts = {})
    # OpenSSL::Cipher loses all encoding informaion upon decoding ciphertext
    # and everything comes out as ASCII. To prevent that, let's just explicitly
    # convert input value to UTF-8 so we can assume the decrypted value will
    # also be unicode.  This is not exactly a wonderful solution, but it's
    # better than just returning ASCII with mangled unicode bytes in it.
    message = message.encode(Encoding::UTF_8) if message

    key_bits = KEYBITS_SELECT[secret.bytesize] || 128
    Generator.new(opts.merge({secret: secret, message: message, key_bits: key_bits})).
      generate
  end

  # Public: verifies a fernet token
  #
  # secret - the secret used to generate the token
  # token  - the token to verify as a string
  # opts   - an optional hash containing
  # * enforce_ttl - whether to enforce TTL in this verification
  # * ttl         - number of seconds token is valid
  #
  # Both enforce_ttl and ttl can be configured globally via Configuration
  #
  # Raises Fernet::Token::InvalidToken if token is invalid and message
  #   is attempted to be extracted
  #
  # Examples
  #
  #   secret = ...
  #   token = ...
  #   verifier = Fernet.verifier(secret, old_token, enforce_ttl: false)
  #   if verifier.valid?
  #     verifier.message # original message in plain text
  #   end
  #
  #   verifier = Fernet.verifier(secret, old_token)
  #   if verifier.valid?
  #     verifier.message
  #   else
  #     verifier.errors
  #     # => { issued_timestamp: "is too far in the past: token expired" }
  #     verifier.error_messages
  #     # => ["issued_timestamp is too far in the past: token expired"]
  #   end
  #
  #   verifier = Fernet.verifier(secret, old_token)
  #   verifier.message
  #   # => raises Fernet::Token::InvalidToken if token too old or invalid
  #
  # Returns a verifier object, which responds to `#valid?` and `#message`
  def self.verifier(secret, token, opts = {})
    Verifier.new(opts.merge({secret: secret, token: token}))
  end
end
