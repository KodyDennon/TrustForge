Gem::Specification.new do |spec|
  spec.name          = "trustforge"
  spec.version       = "0.1.0"
  spec.authors       = ["TrustForge contributors"]
  spec.email         = ["security@trustforge.invalid"]
  spec.summary       = "Rack middleware that gates every request through tf-daemon /v1/decide."
  spec.description   = "TrustForge Rack middleware. Builds a DecideRequest per-request and forwards it to tf-daemon."
  spec.homepage      = "https://github.com/trustforge/trustforge"
  spec.license       = "Apache-2.0"
  spec.required_ruby_version = ">= 2.6.0"

  spec.files = Dir["lib/**/*.rb", "README.md", "trustforge.gemspec"]
  spec.require_paths = ["lib"]

  spec.add_runtime_dependency "rack", ">= 2.0"
  spec.add_development_dependency "rspec", "~> 3.12"
  spec.add_development_dependency "rack-test", "~> 2.1"
end
