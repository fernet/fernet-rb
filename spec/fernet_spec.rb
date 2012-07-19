require 'spec_helper'
require 'fernet'

describe Fernet do
  let(:token_data) do
    { email: 'harold@heroku.com', id: '123', arbitrary: 'data' }
  end

  let(:secret) { 'sekrit123' }

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

    Fernet.verify('bad', token) do |verifier|
      verifier.data['email'] == 'harold@heroku.com'
    end.should be_false
  end

  it 'fails with a bad custom verification' do
    token = Fernet.generate(secret) do |generator|
      generator.data = token_data
    end

    Fernet.verify('bad', token) do |verifier|
      verifier.data['email'] == 'harold@gmail.com'
    end.should be_false
  end

  it 'fails if the token is too old' do
    token = Fernet.generate(secret) do |generator|
      generator.data = token_data
    end

    Fernet.verify('bad', token) do |verifier|
      verifier.seconds_valid = 0
    end.should be_false
  end
end
