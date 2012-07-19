require 'fernet/version'
require 'fernet/generator'
require 'fernet/verifier'

module Fernet
  def self.generate(secret, &block)
    Generator.new(secret).generate(&block)
  end

  def self.verify(secret, token, &block)
    Verifier.new(secret).verify_token(token, &block)
  end
end
