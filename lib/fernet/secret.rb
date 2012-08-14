module Fernet
  class Secret
    def initialize(secret, encrypt)
      @secret  = secret
      @encrypt = encrypt
    end

    def encryption_key
      @secret.byteslice(@secret.bytesize/2, @secret.bytesize)
    end

    def signing_key
      if @encrypt
        @secret.byteslice(0, @secret.bytesize/2)
      else
        @secret
      end
    end
  end
end
