require 'spec_helper'
require 'fernet'

describe Fernet do
  after { Fernet::Configuration.run }

  let(:token_data) do
    { :email => 'harold@heroku.com', :id => '123', :arbitrary => 'data' }
  end

  let(:secret)     { 'JrdICDH6x3M7duQeM8dJEMK4Y5TkBIsYDw1lPy35RiY=' }
  let(:bad_secret) { 'badICDH6x3M7duQeM8dJEMK4Y5TkBIsYDw1lPy35RiY=' }

  it 'can verify tokens it generates' do
    token = Fernet.generate(secret) do |generator|
      generator.data = token_data
    end

    Fernet.verify(secret, token) do |verifier|
      verifier.data['email'] == 'harold@heroku.com'
    end.should be_true
  end

  it 'fails with a bad secret' do
    token = Fernet.generate(secret) do |generator|
      generator.data = token_data
    end

    Fernet.verify(bad_secret, token) do |verifier|
      verifier.data['email'] == 'harold@heroku.com'
    end.should be_false
  end

  it 'fails with a bad custom verification' do
    token = Fernet.generate(secret) do |generator|
      generator.data = token_data
    end

    Fernet.verify(bad_secret, token) do |verifier|
      verifier.data['email'] == 'harold@gmail.com'
    end.should be_false
  end

  it 'fails if the token is too old' do
    token = Fernet.generate(secret) do |generator|
      generator.data = token_data
    end

    Fernet.verify(bad_secret, token) do |verifier|
      verifier.ttl = 0
    end.should be_false
  end

  it 'verifies without a custom verification' do
    token = Fernet.generate(secret) do |generator|
      generator.data = token_data
    end

    Fernet.verify(secret, token).should be_true
  end

  it 'can ignore TTL enforcement' do
    token = Fernet.generate(secret) do |generator|
      generator.data = token_data
    end

    Fernet.verify(secret, token) do |verifier|
      def verifier.now
        Time.now + 99999999999
      end
      verifier.enforce_ttl = false
      true
    end.should be_true
  end

  it 'can ignore TTL enforcement via global config' do
    Fernet::Configuration.run do |config|
      config.enforce_ttl = false
    end

    token = Fernet.generate(secret) do |generator|
      generator.data = token_data
    end

    Fernet.verify(secret, token) do |verifier|
      def verifier.now
        Time.now + 99999999999
      end
      true
    end.should be_true
  end

  it 'generates without custom data' do
    token = Fernet.generate(secret)

    Fernet.verify(secret, token).should be_true
  end

  it 'can encrypt the payload' do
    token = Fernet.generate(secret, true) do |generator|
      generator.data['password'] = 'password1'
    end

    payload = Base64.decode64(token)
    payload.should_not match /password1/

    Fernet.verify(secret, token) do |verifier|
      verifier.data['password'].should == 'password1'
    end
  end

  it 'does not encrypt when asked nicely' do
    token = Fernet.generate(secret, false) do |generator|
      generator.data['password'] = 'password1'
    end

    payload = Base64.decode64(token)
    payload.should match /password1/

    Fernet.verify(secret, token, false) do |verifier|
      verifier.data['password'].should == 'password1'
    end
  end

  it 'can disable encryption via global configuration' do
    Fernet::Configuration.run { |c| c.encrypt = false }
    token = Fernet.generate(secret) do |generator|
      generator.data['password'] = 'password1'
    end

    payload = Base64.decode64(token)
    payload.should match /password1/

    Fernet.verify(secret, token) do |verifier|
      verifier.data['password'].should == 'password1'
    end
  end
end
