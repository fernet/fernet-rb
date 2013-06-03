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
  def self.generate(secret, message = '', opts = {}, &block)
    Generator.new(opts.merge({secret: secret, message: message})).
      generate(&block)
  end

  def self.verifier(secret, token, opts = {})
    Verifier.new(opts.merge({secret: secret, token: token}))
  end
end
