require 'spec_helper'
require 'fernet/secret'

describe Fernet::Secret do
  it "can resolve a URL safe base64 encoded 32 byte string" do
    resolves_input(Base64.urlsafe_encode64("A"*16 + "B"*16), 128)
  end

  it "can resolve a base64 encoded 32 byte string" do
    resolves_input(Base64.encode64("A"*16 + "B"*16), 128)
  end

  it "can resolve a 32 byte string without encoding" do
    resolves_input("A"*16 + "B"*16, 128)
  end

  it "can resolve a URL safe base64 encoded 48 byte string for AES192" do
    resolves_input(Base64.urlsafe_encode64("A"*24 + "B"*24), 192)
  end

  it "can resolve a base64 encoded 48 byte string for AES192" do
    resolves_input(Base64.encode64("A"*24 + "B"*24), 192)
  end

  it "can resolve a 48 byte string without encoding for AES192" do
    resolves_input("A"*24 + "B"*24, 192)
  end

  it "can resolve a URL safe base64 encoded 64 byte string for AES256" do
    resolves_input(Base64.urlsafe_encode64("A"*32 + "B"*32), 256)
  end

  it "can resolve a base64 encoded 64 byte string for AES256" do
    resolves_input(Base64.encode64("A"*32 + "B"*32), 256)
  end

  it "can resolve a 64 byte string without encoding for AES256" do
    resolves_input("A"*32 + "B"*32, 256)
  end

  it "fails loudly when an invalid secret is provided" do
    secret = Base64.urlsafe_encode64("bad")
    expect do
      Fernet::Secret.new(secret, 128)
    end.to raise_error(Fernet::Secret::InvalidSecret)
  end

  def resolves_input(input, key_bits)
    secret = Fernet::Secret.new(input, key_bits)
    key_bytes = key_bits / 8

    expect(
      secret.signing_key
    ).to eq("A"*key_bytes)

    expect(
      secret.encryption_key
    ).to eq("B"*key_bytes)
  end
end
