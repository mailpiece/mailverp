require_relative "lib/mailverp/version"

Gem::Specification.new do |spec|
  spec.name = "mailverp"
  spec.version = MailVerp::VERSION
  spec.platform = Gem::Platform::RUBY
  spec.required_ruby_version = ">= 3.4"
  spec.authors = [ "Simon Lev" ]

  spec.summary = "Signed VERP addresses for Ruby."
  spec.description = "Signed VERP addresses for Ruby. Build a one-off, signed envelope sender for each outbound message, and read the identifier back when a bounce arrives. **mailverp** signs the identifier with an HMAC, so a return path can't be forged or mined for valid addresses."

  spec.homepage = "https://github.com/mailpiece/mailverp"
  spec.license = "MIT"

  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata["bug_tracker_uri"] = "#{spec.homepage}/issues"
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir[
    "lib/**/*.rb",
    "CHANGELOG.md",
    "README.md",
    "LICENSE",
    "mailverp.gemspec"
  ]
  spec.require_paths = [ "lib" ]
end
