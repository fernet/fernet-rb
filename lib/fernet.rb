require 'fernet/version'
require 'fernet/generator'
require 'fernet/verifier'
require 'fernet/secret'

if RUBY_VERSION == '1.8.7'
  require 'shim/base64'
end

module Fernet
  def self.generate(secret, encrypt = true, &block)
    Generator.new(secret, encrypt).generate(&block)
  end

  def self.verify(secret, token, decrypt = true, &block)
    Verifier.new(secret, decrypt).verify_token(token, &block)
  end
end
