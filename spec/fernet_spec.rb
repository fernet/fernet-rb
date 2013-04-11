require 'spec_helper'
require 'fernet'

describe Fernet do
  after { Fernet::Configuration.run }

  let(:secret)     { 'JrdICDH6x3M7duQeM8dJEMK4Y5TkBIsYDw1lPy35RiY=' }
  let(:bad_secret) { 'badICDH6x3M7duQeM8dJEMK4Y5TkBIsYDw1lPy35RiY=' }

  it 'can verify tokens it generates' do
    token = Fernet.generate(secret) do |generator|
      generator.data = 'harold@heroku.com'
    end

    expect(
      Fernet.verify(secret, token) do |verifier|
        verifier.data == 'harold@heroku.com'
      end
    ).to be_true
  end

  it 'fails with a bad secret' do
    token = Fernet.generate(secret) do |generator|
      generator.data = 'harold@heroku.com'
    end

    expect(
      Fernet.verify(bad_secret, token) do |verifier|
        verifier.data == 'harold@heroku.com'
      end
    ).to be_false
  end

  it 'fails with a bad custom verification' do
    token = Fernet.generate(secret) do |generator|
      generator.data = 'harold@heroku.com'
    end

    expect(
      Fernet.verify(secret, token) do |verifier|
        verifier.data == 'lol@heroku.com'
      end
    ).to be_false
  end

  it 'fails if the token is too old' do
    token = Fernet.generate(secret) do |generator|
      generator.data = 'harold@heroku.com'
    end

    expect(
      Fernet.verify(secret, token) do |verifier|
        verifier.ttl = 1

        def verifier.now
          now = DateTime.now
          DateTime.new(now.year, now.month, now.day, now.hour,
                       now.min, now.sec + 2, now.offset)
        end
        true
      end
    ).to be_false
  end

  it 'verifies without a custom verification' do
    token = Fernet.generate(secret) do |generator|
      generator.data = 'harold@heroku.com'
    end

    expect(Fernet.verify(secret, token)).to be_true
  end

  it 'can ignore TTL enforcement' do
    # Make sure the global value is set to true
    Fernet::Configuration.run do |config|
      config.enforce_ttl = true
    end

    token = Fernet.generate(secret) do |generator|
      generator.data = 'harold@heroku.com'
    end

    expect(
      Fernet.verify(secret, token) do |verifier|
        def verifier.now
          DateTime.now + 99999999999
        end
        verifier.enforce_ttl = false
        true
      end
    ).to be_true
  end

  it 'can ignore TTL enforcement via global config' do
    Fernet::Configuration.run do |config|
      config.enforce_ttl = false
    end

    token = Fernet.generate(secret) do |generator|
      generator.data = 'harold@heroku.com'
    end

    expect(
      Fernet.verify(secret, token) do |verifier|
        def verifier.now
          Time.now + 99999999999
        end
        true
      end
    ).to be_true
  end

  it 'encrypts the payload' do
    token = Fernet.generate(secret) do |generator|
      generator.data = 'password1'
    end

    expect(Base64.decode64(token)).not_to match /password1/

    Fernet.verify(secret, token) do |verifier|
      expect(verifier.data).to eq('password1')
    end
  end

  it 'allows overriding enforce_ttl on a verifier' do
    Fernet::Configuration.run do |config|
      config.enforce_ttl = true
      config.ttl = 0
    end
    token = Fernet.generate(secret) do |generator|
      generator.data = 'password1'
    end
    verifier = Fernet.verifier(secret, token)
    verifier.enforce_ttl = false
    expect(verifier.valid?).to be_true
    expect(verifier.data).to eq('password1')
  end

  it 'allows overriding enforce_ttl on verifier block' do
    Fernet::Configuration.run do |config|
      config.enforce_ttl = true
      config.ttl = 0
    end
    token = Fernet.generate(secret) do |generator|
      generator.data = 'password1'
    end
    verifier = Fernet.verifier(secret, token) do |v|
      v.enforce_ttl = false
      true
    end
    expect(verifier.data).to eq('password1')
    expect(verifier.valid?).to be_true
  end
end
