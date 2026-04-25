Gem::Specification.new do |spec|
  spec.name          = "trustforge-hanami"
  spec.version       = "0.1.0"
  spec.authors       = ["TrustForge contributors"]
  spec.email         = ["security@trustforge.invalid"]
  spec.summary       = "Hanami middleware for TrustForge."
  spec.description   = "Hanami-2 compatible middleware that gates requests through tf-daemon."
  spec.homepage      = "https://github.com/trustforge/trustforge"
  spec.license       = "Apache-2.0"
  spec.required_ruby_version = ">= 2.6.0"

  spec.files = Dir["lib/**/*.rb", "README.md", "trustforge-hanami.gemspec"]
  spec.require_paths = ["lib"]

  spec.add_runtime_dependency "trustforge", "~> 0.1"
  spec.add_development_dependency "rspec", "~> 3.12"
  spec.add_development_dependency "rack-test", "~> 2.1"
end
