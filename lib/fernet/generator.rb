#encoding UTF-8
require 'base64'
require 'openssl'
require 'date'

module Fernet
  class Generator
    attr_accessor :message

    def initialize(opts)
      @secret  = opts.fetch(:secret)
      @message = opts[:message]
      @iv      = opts[:iv]
      @now     = opts[:now]
    end

    def generate
      yield self if block_given?

      token = Token.generate(secret:  @secret,
                             message: @message,
                             iv:      @iv,
                             now:     @now)
      token.to_s
    end

    def inspect
      "#<Fernet::Generator @secret=[masked] @message=#{@message.inspect}>"
    end
    alias to_s inspect

    def data=(message)
      puts "[WARNING] 'data' is deprecated, use 'message' instead"
      @message = message
    end
  end
end
