#encoding UTF-8
require 'base64'
require 'openssl'
require 'date'

module Fernet
  # Internal: Generates Fernet tokens
  class Generator
    # Returns the token's message
    attr_accessor :message

    # Internal: Initializes a generator
    #
    # opts - a hash containing the following keys:
    #   secret: a string containing a secret, optionally Base64 encoded
    #   message: the message
    def initialize(opts)
      @secret  = opts.fetch(:secret)
      @message = opts[:message]
      @iv      = opts[:iv]
      @now     = opts[:now]
    end

    # Internal: generates a secret token
    #
    # Yields itself, useful for setting or overriding the message
    #
    # Returns the token as a string
    #
    # Examples
    # generator = Generator.new(secret: some_secret)
    # token = generator.generate do |g|
    #   g.message = 'this is my message'
    # end
    #
    # generator = Generator.new(secret: some_secret,
    #                           message: 'this is my message')
    # token = generator.generate
    def generate
      yield self if block_given?

      token = Token.generate(secret:  @secret,
                             message: @message,
                             iv:      @iv,
                             now:     @now)
      token.to_s
    end

    # Public: string representation of this generator, masks secret to avoid
    #   leaks
    def inspect
      "#<Fernet::Generator @secret=[masked] @message=#{@message.inspect}>"
    end
    alias to_s inspect

    # Deprecated: used to set the message
    def data=(message)
      puts "[WARNING] 'data=' is deprecated, use 'message=' instead"
      @message = message
    end
  end
end
