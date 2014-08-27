module Snmp4JR
  class Inform

    attr_accessor :host, :port, :community, :timeout, :version, :transport, :retries

    DEFAULTS = {
      host: '127.0.0.1',
      port: 161,
      transport: 'udp',
      timeout: 3000,
      retries: 0,
      version: Snmp4JR::MP::Version2c,
      community: 'public',
      oid: '.1.3.6.1.2.1.1.8'
    }

    def initialize(opts = {})
      opts = DEFAULTS.merge(opts)

      self.host = opts[:host]
      self.port = opts[:port]
      self.community = opts[:community]
      self.timeout = opts[:timeout]
      self.version = opts[:version]
      self.transport = opts[:transport]
      self.retries = opts[:retries]
    end

    def add(key, value)
      pdu.add(Snmp4JR::SMI::VariableBinding.new(key, value))
    end

    def send
      pdu.setType(Snmp4JR::PDU::INFORM)
      snmp.send(pdu, snmp_target)
      snmp.close
    end

    private

    def pdu
      return @pdu if @pdu
      @pdu = Snmp4JR::PDU.new
      @pdu
    end

    def snmp
      return @snmp if @snmp
      @snmp = Snmp4JR::Snmp.new(snmp_transport)
      @snmp
    end

    def snmp_target
      return @snmp_target if @snmp_target

      @snmp_target = Snmp4JR::CommunityTarget.new
      @snmp_target.community = Snmp4JR::SMI::OctetString.new(community)
      @snmp_target.version = version
      @snmp_target.timeout = timeout
      @snmp_target.retries = retries
      @snmp_target.address = Snmp4JR::SMI::GenericAddress.parse("#{transport}:#{host}/#{port}")

      @snmp_target
    end

    def snmp_transport
      return @snmp_transport if @snmp_transport

      case transport
      when 'udp'
        @snmp_transport = Snmp4JR::Transport::DefaultUdpTransportMapping.new
      when 'tcp'
        @snmp_transport = Snmp4JR::Transport::DefaultTcpTransportMapping.new
      else
        @snmp_transport = Snmp4JR::Transport::DefaultUdpTransportMapping.new
      end

      @snmp_transport.listen

      @snmp_transport
    end
  end
end
