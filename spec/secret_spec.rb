require 'spec_helper'
require 'fernet/secret'

describe Fernet::Secret do
  it "can resolve a URL safe base64 encoded 32 byte string" do
    resolves_input(Base64.urlsafe_encode64("A"*16 + "B"*16))
  end

  it "can resolve a base64 encoded 32 byte string" do
    resolves_input(Base64.encode64("A"*16 + "B"*16))
  end

  it "fails loudly when an invalid secret is provided" do
    secret = Base64.urlsafe_encode64("bad")
    expect do
      Fernet::Secret.new(secret)
    end.to raise_error(Fernet::Secret::InvalidSecret)
  end

  def resolves_input(input)
    secret = Fernet::Secret.new(input)

    expect(
      secret.signing_key
    ).to eq("A"*16)

    expect(
      secret.encryption_key
    ).to eq("B"*16)
  end
end
