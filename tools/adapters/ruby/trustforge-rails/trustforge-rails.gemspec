Gem::Specification.new do |spec|
  spec.name          = "trustforge-rails"
  spec.version       = "0.1.0"
  spec.authors       = ["TrustForge contributors"]
  spec.email         = ["security@trustforge.invalid"]
  spec.summary       = "Rails engine for TrustForge."
  spec.description   = "Inserts the TrustForge::Rack middleware into a Rails application."
  spec.homepage      = "https://github.com/trustforge/trustforge"
  spec.license       = "Apache-2.0"
  spec.required_ruby_version = ">= 2.6.0"

  spec.files = Dir["lib/**/*.rb", "README.md", "trustforge-rails.gemspec"]
  spec.require_paths = ["lib"]

  spec.add_runtime_dependency "trustforge", "~> 0.1"
  spec.add_runtime_dependency "railties", ">= 6.0"
  spec.add_development_dependency "rspec", "~> 3.12"
end
