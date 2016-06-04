require 'spec_helper'
require 'fernet'
require 'json'
require 'base64'

describe Fernet::Verifier do
  it 'verifies tokens according to the spec for AES128' do
    path = File.expand_path(
      './../fernet-spec/verify.json', File.dirname(__FILE__)
    )
    verify_json  = JSON.parse(File.read(path))

    verify_json.each do |test_data|
      token   = test_data['token']
      ttl     = test_data['ttl_sec']
      now     = DateTime.parse(test_data['now']).to_time
      secret  = test_data['secret']
      message = test_data['src']

      verifier = Fernet::Verifier.new(token: token,
                                      secret: secret,
                                      now: now,
                                      ttl: ttl)
      expect(
        verifier.message
      ).to eq(message)
    end
  end

  it 'verifies tokens according to the spec for AES192' do
    path = File.expand_path(
      './../fernet-spec/verify.json', File.dirname(__FILE__)
    )
    verify_json  = JSON.parse(File.read(path))

    verify_json.each do |test_data|
      token   = test_data['token']
      ttl     = test_data['ttl_sec']
      now     = DateTime.parse(test_data['now']).to_time
      secret  = test_data['secret']
      message = test_data['src']

      verifier = Fernet::Verifier.new(token: token,
                                      secret: secret,
                                      now: now,
                                      ttl: ttl)
      expect(
        verifier.message
      ).to eq(message)
    end
  end

  it 'verifies tokens according to the spec for AES256' do
    path = File.expand_path(
      './../fernet-spec/verify.json', File.dirname(__FILE__)
    )
    verify_json  = JSON.parse(File.read(path))

    verify_json.each do |test_data|
      token   = test_data['token']
      ttl     = test_data['ttl_sec']
      now     = DateTime.parse(test_data['now']).to_time
      secret  = test_data['secret']
      message = test_data['src']

      verifier = Fernet::Verifier.new(token: token,
                                      secret: secret,
                                      now: now,
                                      ttl: ttl)
      expect(
        verifier.message
      ).to eq(message)
    end
  end

  context 'invalid tokens' do
    path = File.expand_path(
      './../fernet-spec/invalid.json', File.dirname(__FILE__)
    )
    invalid_json = JSON.parse(File.read(path))
    invalid_json.each do |test_data|
      it "detects #{test_data['desc']}" do
        token  = test_data['token']
        ttl    = test_data['ttl_sec']
        now    = DateTime.parse(test_data['now']).to_time
        secret = test_data['secret']

        verifier = Fernet::Verifier.new(token: token,
                                        secret: secret,
                                        now: now,
                                        ttl: ttl)

        expect { verifier.message }.to raise_error(Fernet::Token::InvalidToken)
      end
    end
  end

end
