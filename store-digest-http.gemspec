# -*- mode: enh-ruby -*-
require_relative 'lib/store/digest/http/version'

Gem::Specification.new do |spec|
  spec.name          = "store-digest-http"
  spec.version       = Store::Digest::HTTP::VERSION
  spec.authors       = ["Dorian Taylor"]
  spec.email         = ["code@doriantaylor.com"]
  spec.license       = 'Apache-2.0'
  spec.homepage      = "https://github.com/doriantaylor/rb-store-digest-http"
  spec.summary       = %q{HTTP front-end to Store::Digest}

  spec.metadata["homepage_uri"] = spec.homepage

  # Specify which files should be added to the gem when it is
  # released. The `git ls-files -z` loads the files in the RubyGem
  # that have been added into git.
  spec.files         = Dir.chdir(File.expand_path('..', __FILE__)) do
    `git ls-files -z`.split("\x0").reject do |f|
      f.match(%r{^(test|spec|features)/})
    end
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # ruby
  spec.required_ruby_version = '>= 2.7'

  # dev/test dependencies
  spec.add_development_dependency 'bundler', '>= 2.1'
  spec.add_development_dependency 'rake',    '>= 13.0'
  spec.add_development_dependency 'rspec',   '>= 3.9'

  # stuff we use
  spec.add_runtime_dependency 'rack',      '>= 2.2'
  spec.add_runtime_dependency 'commander', '>= 4.5'

  # stuff i wrote
  spec.add_runtime_dependency 'store-digest', '>= 0.1.4'
  spec.add_runtime_dependency 'uri-ni',       '>= 0.1.5'
  spec.add_runtime_dependency 'xml-mixup',    '>= 0.1.17'
end
