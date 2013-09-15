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
  # Public: generates a fernet token
  #
  # secret  - a base64 encoded, 32 byte string
  # message - the message being secured in plain text
  #
  # Returns the fernet token as a string
  #
  # Examples
  #
  #   secret = ...
  #   token = Fernet.generate(secret, 'my secrets')
  def self.generate(secret, message = '', opts = {}, &block)
    Generator.new(opts.merge({secret: secret, message: message})).
      generate(&block)
  end

  # Public: verifies a fernet token
  #
  # secret - the secret used to generate the token
  # token  - the token to verify as a string
  # opts - an optional hash containing
  #   enforce_ttl: whether to enforce TTL in this verification
  #   ttl: number of seconds token is valid
  #
  # Both enforce_ttl and ttl can be configured globally via Configuration
  #
  # Returns a verifier object, which responds to valid? and message
  #
  # Raises Fernet::Token::InvalidToken if token is invalid and message
  #   is attempted to be extracted
  #
  # Examples
  #
  # secret = ...
  # token = ...
  # verifier = Fernet.verifier(secret, old_token, enforce_ttl: false)
  # if verifier.valid?
  #   verifier.message # original message in plain text
  # end
  #
  # verifier = Fernet.verifier(secret, old_token)
  # if verifier.valid?
  #   verifier.message
  # else
  #   verifier.errors
  #   # -> { issued_timestamp: "is too far in the past: token expired" }
  #   verifier.error_messages
  #   # -> ["issued_timestamp is too far in the past: token expired"]
  # end
  #
  def self.verifier(secret, token, opts = {})
    Verifier.new(opts.merge({secret: secret, token: token}))
  end
end
