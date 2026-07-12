Gem::Specification.new do |spec|
  spec.name = "demo"
  spec.extensions = ["ext/demo/extconf.rb"]
end
Gem.post_install { |_installer| true }
