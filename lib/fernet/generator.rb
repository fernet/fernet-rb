require 'base64'
require 'json'
require 'openssl'
require 'date'

module Fernet
  class Generator
    attr_reader :secret
    attr_accessor :data

    def initialize(secret)
      @secret = secret
    end

    def generate
      yield self
      data.merge!(issued_at: DateTime.now)

      mac = OpenSSL::HMAC.hexdigest('sha256', JSON.dump(data), secret)
      Base64.urlsafe_encode64(JSON.dump(data.merge(signature: mac)))
    end

  end
end
