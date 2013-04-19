require 'fernet/version'
require 'fernet/bit_packing'
require 'fernet/generator'
require 'fernet/verifier'
require 'fernet/secret'
require 'fernet/configuration'

if RUBY_VERSION == '1.8.7'
  require 'shim/base64'
end

Fernet::Configuration.run

module Fernet
  def self.generate(secret, message = '', &block)
    Generator.new(secret, message).generate(&block)
  end

  def self.verify(secret, token, &block)
    Verifier.new(secret, :token => token).verify(&block)
  end

  def self.verifier(secret, token, &block)
    Verifier.new(secret, :token => token).tap do |v|
      v.verify(&block)
    end
  end
end
