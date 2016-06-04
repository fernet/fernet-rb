require 'spec_helper'
require 'fernet'
require 'json'
require 'base64'

describe Fernet::Generator do
  it 'generates tokens according to the spec for AES128' do
    path = File.expand_path(
      './../fernet-spec/generate.json', File.dirname(__FILE__)
    )
    generate_json  = JSON.parse(File.read(path))
    generate_json.each do |test_data|
      message        = test_data['src']
      iv             = test_data['iv'].pack("C*")
      secret         = test_data['secret']
      now            = DateTime.parse(test_data['now']).to_time
      expected_token = test_data['token']

      generator = Fernet::Generator.new(secret:   secret,
                                        message:  message,
                                        iv:       iv,
                                        now:      now)

      expect(generator.generate).to eq(expected_token)
    end
  end

  it 'generates tokens according to the spec for AES192' do
    path = File.expand_path(
      './../fernet-spec/generate_192.json', File.dirname(__FILE__)
    )
    generate_json  = JSON.parse(File.read(path))
    generate_json.each do |test_data|
      message        = test_data['src']
      iv             = test_data['iv'].pack("C*")
      secret         = test_data['secret']
      now            = DateTime.parse(test_data['now']).to_time
      expected_token = test_data['token']

      generator = Fernet::Generator.new(secret:   secret,
                                        key_bits: 192,
                                        message:  message,
                                        iv:       iv,
                                        now:      now)

      expect(generator.generate).to eq(expected_token)
    end
  end

  it 'generates tokens according to the spec for AES256' do
    path = File.expand_path(
      './../fernet-spec/generate_256.json', File.dirname(__FILE__)
    )
    generate_json  = JSON.parse(File.read(path))
    generate_json.each do |test_data|
      message        = test_data['src']
      iv             = test_data['iv'].pack("C*")
      secret         = test_data['secret']
      now            = DateTime.parse(test_data['now']).to_time
      expected_token = test_data['token']

      generator = Fernet::Generator.new(secret:   secret,
                                        key_bits: 256,
                                        message:  message,
                                        iv:       iv,
                                        now:      now)

      expect(generator.generate).to eq(expected_token)
    end
  end

end
