
if RUBY_PLATFORM =~ /java/
  require 'java'
  require 'log4j-1.2.9.jar'
  require 'snmp4j-2.3.0.jar'
else
  warn 'snmp4jr can only be used with JRuby'
  exit 1
end

module Snmp4JR
  include_package 'org.snmp4j'

  module Constants
    GET          = -96
    GETNEXT      = -95
    GETBULK      = -91
    INFORM       = -90
    NOTIFICATION = -89
    REPORT       = -88
    RESPONSE     = -94
    SET          = -93
    TRAP         = -89
    V1TRAP       = -92
  end

  module ASN1
    include_package 'org.snmp4j.asn1'
  end

  module Event
    include_package 'org.snmp4j.event'
  end

  module Log
    include_package 'org.snmp4j.log'
  end

  module MP
    Version1  = 0
    Version2c = 1
    Version3  = 3
    include_package 'org.snmp4j.mp'
  end

  module Security
    include_package 'org.snmp4j.security'
  end

  module SMI
    include_package 'org.snmp4j.smi'
  end

  module Test
    include_package 'org.snmp4j.test'
  end

  module Tools
    module Console
      include_package 'org.snmp4j.tools.console'
    end
  end

  module Transport
    include_package 'org.snmp4j.transport'
  end

  module Util
    include_package 'org.snmp4j.util'
  end

  module Version
    include_package 'org.snmp4j.version'
  end
end

require 'snmp4jr/manager'
