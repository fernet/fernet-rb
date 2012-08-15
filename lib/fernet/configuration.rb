require 'singleton'
module Fernet
  class Configuration
    include Singleton

    # Whether to enforce a message TTL
    # (true or false)
    attr_accessor :enforce_ttl

    # How long messages are considered valid to the verifier
    # (an integer in seconds)
    attr_accessor :ttl

    # Whether to encrypt the payload
    # (true or false)
    attr_accessor :encrypt

    def self.run
      self.instance.enforce_ttl = true
      self.instance.ttl         = 60
      self.instance.encrypt     = true
      yield self.instance if block_given?
    end

    class << self
      def method_missing(method)
        if self.instance.respond_to?(method)
          self.instance.send(method)
        else
          super
        end
      end

      def respond_to?(method)
        self.instance.respond_to?(method) || super
      end
    end
  end
end
