# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'snmp4jr/version'

Gem::Specification.new do |s|
  s.name    = 'snmp4jr'
  s.version = Snmp4JR::VERSION
  s.license = 'MIT'

  s.summary     = "JRuby wrapper for SNMP4J."
  s.description = "JRuby wrapper for SNMP4J."

  s.authors  = ["Michael Zaccari"]
  s.email    = 'michael.zaccari@gmail.com'
  s.homepage = 'https://github.com/mzaccari/snmp4jr'

  all_files       = `git ls-files -z`.split("\x0")
  s.files         = all_files.grep(%r{^(bin|lib)/})
  s.executables   = all_files.grep(%r{^bin/}) { |f| File.basename(f) }
  s.require_paths = ["lib"]
end
