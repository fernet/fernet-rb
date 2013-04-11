require 'spec_helper'
require 'fernet'

describe Fernet do
  after { Fernet::Configuration.run }

  let(:token_data) do
    Yajl::Encoder.encode({
      :email     => 'harold@heroku.com',
      :id        => '123',
      :arbitrary => 'data'
    })
  end

  let(:secret)     { 'JrdICDH6x3M7duQeM8dJEMK4Y5TkBIsYDw1lPy35RiY=' }
  let(:bad_secret) { 'badICDH6x3M7duQeM8dJEMK4Y5TkBIsYDw1lPy35RiY=' }

  it 'can verify tokens it generates' do
    token = Fernet.generate(secret) do |generator|
      generator.data = token_data
    end

    expect(
      Fernet.verify(secret, token) do |verifier|
        Yajl::Parser.parse(verifier.data)['email'] == 'harold@heroku.com'
      end
    ).to be_true
  end

  it 'fails with a bad secret' do
    token = Fernet.generate(secret) do |generator|
      generator.data = token_data
    end

    expect(
      Fernet.verify(bad_secret, token) do |verifier|
        verifier.data['email'] == 'harold@heroku.com'
      end
    ).to be_false
  end

  it 'fails with a bad custom verification' do
    token = Fernet.generate(secret) do |generator|
      generator.data = Yajl::Encoder.encode({ :email => 'harold@heroku.com' })
    end

    expect(
      Fernet.verify(secret, token) do |verifier|
        Yajl::Parser.parse(verifier.data)['email'] == 'lol@heroku.com'
      end
    ).to be_false
  end

  it 'fails if the token is too old' do
    token = Fernet.generate(secret) do |generator|
      generator.data = token_data
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
      generator.data = token_data
    end

    expect(Fernet.verify(secret, token)).to be_true
  end

  it 'can ignore TTL enforcement' do
    token = Fernet.generate(secret) do |generator|
      generator.data = token_data
    end

    expect(
      Fernet.verify(secret, token) do |verifier|
        def verifier.now
          Time.now + 99999999999
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
      generator.data = token_data
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
end
