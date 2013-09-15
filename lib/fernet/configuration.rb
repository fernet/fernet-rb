require 'singleton'
module Fernet
  # Public - singleton class used to globally set various
  #          configuration defaults
  class Configuration
    include Singleton

    # Public: Returns whether to enforce a message TTL (true or false)
    attr_accessor :enforce_ttl

    # Public: Returns how many seconds messages are considered valid for
    attr_accessor :ttl

    # Public: used to configure fernet, typically invoked in an initialization
    #   routine
    #
    # Sets the following values:
    #
    # * enforce_ttl: true
    # * ttl: 60
    #
    # Yields the singleton configuration object, where above defaults can be
    #   overridden
    #
    # Examples
    #
    # Fernet::Configuration.run do |config|
    #   config.enforce_ttl = false
    # end
    def self.run
      self.instance.enforce_ttl = true
      self.instance.ttl         = 60
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
