#encoding UTF-8
require 'base64'
require 'openssl'
require 'date'

module Fernet
  # Internal: Generates Fernet tokens
  class Generator
    # Internal: Returns the token's message
    attr_accessor :message

    # Internal: Initializes a generator
    #
    # opts - a hash containing the following keys:
    # * key_bits - number of bits in the AES key, defaults to 128
    # * secret   - a string containing a secret, optionally Base64 encoded
    # * message  - the message
    def initialize(opts)
      @key_bits = opts[:key_bits] || 128
      @secret   = opts.fetch(:secret)
      @message  = opts[:message]
      @iv       = opts[:iv]
      @now      = opts[:now]
    end

    # Internal: generates a secret token
    #
    # Yields itself, useful for setting or overriding the message
    #
    # Examples
    #
    #   generator = Generator.new(secret: some_secret)
    #   token = generator.generate do |g|
    #     g.message = 'this is my message'
    #   end
    #
    #   generator = Generator.new(secret: some_secret,
    #                             message: 'this is my message')
    #   token = generator.generate
    #
    # Returns the token as a string
    def generate
      yield self if block_given?

      token = Token.generate(key_bits: @key_bits,
                             secret:   @secret,
                             message:  @message,
                             iv:       @iv,
                             now:      @now)
      token.to_s
    end

    # Public: string representation of this generator, masks secret to avoid
    #   leaks
    def inspect
      "#<Fernet::Generator @key_bits=#{@key_bits} @secret=[masked] @message=#{@message.inspect}>"
    end
    alias to_s inspect

    # Deprecated: used to set the message
    def data=(message)
      puts "[WARNING] 'data=' is deprecated, use 'message=' instead"
      @message = message
    end
  end
end
