module Fernet
  class Secret
    def initialize(secret)
      @secret  = secret
    end

    def encryption_key
      decoded_secret.slice(decoded_secret.size/2, decoded_secret.size)
    end

    def signing_key
      decoded_secret.slice(0, decoded_secret.size/2)
    end

  private
    def decoded_secret
      @decoded_secret ||= Base64.decode64(@secret)
    end
  end
end
