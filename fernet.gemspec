# -*- encoding: utf-8 -*-
require File.expand_path('../lib/fernet/version', __FILE__)

Gem::Specification.new do |gem|
  gem.authors      = ["Harold Giménez"]
  gem.email        = ["harold.gimenez@gmail.com"]
  gem.description  = "Delicious HMAC Digest(if) authentication and AES-128-CBC encryption"
  gem.summary      = "Easily generate and verify AES encrypted HMAC based authentication tokens"
  gem.homepage     = "https://github.com/fernet/fernet-rb"

  gem.files        = Dir["LICENSE", "README.md", "lib/**/**"]
  gem.name         = "fernet"
  gem.require_path = "lib"
  gem.version      = Fernet::VERSION

  gem.add_runtime_dependency     "valcro", "0.1"
  gem.add_development_dependency "rspec",  "~> 3.4"
  gem.add_development_dependency "rake",  "~> 10.4"
end
