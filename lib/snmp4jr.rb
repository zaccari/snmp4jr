
if RUBY_PLATFORM =~ /java/
  require 'java'
  require 'log4j-1.2.9.jar'
  require 'snmp4j-2.3.0.jar'
else
  warn 'snmp4jr can only be used with JRuby'
  exit 1
end
