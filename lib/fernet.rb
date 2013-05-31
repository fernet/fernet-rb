require 'fernet/version'
require 'fernet/bit_packing'
require 'fernet/generator'
require 'fernet/verifier'
require 'fernet/secret'
require 'fernet/configuration'

Fernet::Configuration.run

module Fernet
  TOKEN_VERSION = 0x80.freeze

  def self.generate(secret, message = '', &block)
    Generator.new(secret: secret, message: message).generate(&block)
  end

  def self.verify(secret, token, &block)
    Verifier.new(secret: secret, token: token).verify(&block)
  end

  def self.verifier(secret, token, &block)
    Verifier.new(secret: secret, token: token).tap do |v|
      v.verify(&block)
    end
  end
end
