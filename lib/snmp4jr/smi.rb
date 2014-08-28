require 'snmp4j-smi-pro.jar'

module Snmp4JR
  module SMI
    include_package 'com.snmp4j.smi'
    include_package 'org.snmp4j.smi'

    module Util
      include_package 'com.snmp4j.smi.util'
      include_package 'org.snmp4j.smi.util'
    end
  end
end
