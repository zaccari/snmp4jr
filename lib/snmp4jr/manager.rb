module Snmp4JR
  class Manager

    attr_reader :request_type, :snmp, :result, :pdus_sent, :pdu

    attr_accessor :host, :community, :timeout, :version, :max_repetitions,
      :non_repeaters, :port, :username, :security_level, :auth_password,
      :auth_protocol, :priv_password, :priv_protocol

    DEFAULTS = {
      host: '127.0.0.1',
      port: 161,
      transport: 'udp',
      timeout: 3000,
      version: Snmp4JR::MP::Version2c,
      community: 'public',
      oids: ['1.3.6.1.2.1.1.1', '1.3.6.1.2.1.1.5'],
      max_repetitions: 1,
      non_repeaters: 2,
      request_type: Snmp4JR::Constants::GET
    }

    def initialize(opts = {})
      opts = DEFAULTS.merge(opts)

      self.host = opts[:host]
      self.community = opts[:community]
      self.timeout = opts[:timeout]
      self.version = opts[:version]
      self.transport = opts[:transport]
      self.oids = opts[:oids]
      self.max_repetitions = opts[:max_repetitions]
      self.non_repeaters = opts[:non_repeaters]
      self.port = opts[:port]

      # v3 settings
      self.username = opts[:username]
      self.security_level = opts[:security_level]
      self.auth_password = opts[:auth_password]
      self.auth_protocol = opts[:auth_protocol]
      self.priv_password = opts[:priv_password]
      self.priv_protocol = opts[:priv_protocol]

      @result = []
      @pdus_sent = 0
      @request_type = opts[:request_type]
    end

    def close
      unless @pdu.nil?
        @pdu.clear
        @pdu = nil
      end

      unless @snmp_target.nil?
        @snmp_target = nil
      end
    end

    def snmp_target
      return @snmp_target unless @snmp_target.nil?

      if authenticated?
        @snmp_target = Snmp4JR::UserTarget.new
        @snmp_target.set_security_level(Snmp4JR::Security::SecurityLevel::AUTH_PRIV)
        @snmp_target.set_security_name(Snmp4JR::SMI::OctetString.new(username))
      else
        @snmp_target = Snmp4JR::CommunityTarget.new
        @snmp_target.community = Snmp4JR::SMI::OctetString.new(community)
      end

      @snmp_target.address = Snmp4JR::SMI::GenericAddress.parse("#{@transport}:#{@host}/#{@port}")
      @snmp_target.version = @version
      @snmp_target.timeout = @timeout
      @snmp_target
    end

    def snmp_target=(target)
      @snmp_target = target
    end

    def snmp
      return @snmp if @snmp

      if authenticated?
        address = Snmp4JR::SMI::GenericAddress.parse("#{@transport}:#{@host}/#{@port}")

        usm = Snmp4JR::Security::USM.new(Snmp4JR::Security::SecurityProtocols.instance,
                                         Snmp4JR::SMI::OctetString.new(Snmp4JR::MP::MPv3.create_local_engine_id),
                                         0)
        Snmp4JR::Security::SecurityModels.instance.add_security_model(usm)

        @snmp = Snmp4JR::Snmp.new(self.transport)

        # TODO: Add support for different auth types
        @snmp.usm.add_user(Snmp4JR::SMI::OctetString.new(@username),
                           Snmp4JR::Security::UsmUser.new(Snmp4JR::SMI::OctetString.new(@username),
                                                          Snmp4JR::Security::AuthMD5::ID,
                                                          Snmp4JR::SMI::OctetString.new(@auth_password),
                                                          Snmp4JR::Security::PrivDES::ID,
                                                          Snmp4JR::SMI::OctetString.new(@priv_password)))
      else
        @snmp = Snmp4JR::Snmp.new(self.transport)
      end

      @snmp
    end

    def oids
      if @oids.class == String
        @oids = [@oids]
      end
      return @oids
    end

    def oids=(oids)
      @oids = oids
    end

    def transport
      if @transport.class == String
        case @transport
        when 'udp'
          return Snmp4JR::Transport::DefaultUdpTransportMapping.new
        when 'tcp'
          return Snmp4JR::Transport::DefaultTcpTransportMapping.new
        else
          return Snmp4JR::Transport::DefaultUdpTransportMapping.new
        end
      else
        return @transport
      end
    end

    def transport=(ivar)
      @transport = ivar
    end

    def get(oid = nil)
      self.oids = [oid] unless oid.nil?
      @request_type = Snmp4JR::Constants::GET
      reset_session
      snmp.listen

      event = snmp.send(pdu, snmp_target)

      if event.response.nil?
        @result = nil
      else
        @result = event.response.variable_bindings.first.variable
      end

      snmp.close

      @result
    end

    def get_all(oid_list = nil)
      self.oids = oid_list unless oid_list.nil?
      @request_type = Snmp4JR::Constants::GET
      reset_session
      snmp.listen

      event = snmp.send(pdu, snmp_target)

      unless event.response.nil?
        @result = event.response.variable_bindings
      end

      snmp.close

      @result
    end

    def get_bulk(oid_list = nil)
      self.oids = oid_list unless oid_list.nil?
      @request_type = Snmp4JR::Constants::GETBULK
      reset_session
      snmp.listen
      event = snmp.send(pdu, snmp_target)
      if event.response.nil?
        @result = []
        return nil
      else
        @result = event.response.variable_bindings
      end
      snmp.close
      @result
    end

    def set(oid = '1.3.6.1.2.1.1.4.0', variable = Snmp4JR::SMI::OctetString.new('mark.cotner@gmail.com'))
      set_pdu = version_3? ? Snmp4JR::ScopedPDU.new : Snmp4JR::PDU.new
      set_pdu.type = Snmp4JR::Constants::SET
      set_pdu.add(Snmp4JR::SMI::VariableBinding.new(Snmp4JR::SMI::OID.new(oid), variable))
      set_pdu.non_repeaters = 0
      snmp.listen
      event = snmp.set(set_pdu, snmp_target)
      if event.response.nil?
        @result = []
        return nil
      end
      return event.response.variable_bindings.get 0
    end

    def walk(oid = nil)
      self.oids = [oid] unless oid.nil?
      return nil if oid.nil?
      snmp_oid = Snmp4JR::SMI::OID.new(oid)
      case version
      when Snmp4JR::MP::Version1
        @request_type = Snmp4JR::Constants::GETNEXT
      when (Snmp4JR::MP::Version2c or Snmp4JR::MP::Version3)
        @request_type = Snmp4JR::Constants::GETBULK
        @max_repetitions = 40
        @non_repeaters = 0
      end
      # tick a pdu for async to return when complete
      @pdus_sent += 1
      # track when I'm finished polling
      finished = false
      @result = []
      snmp.listen
      until finished
        response_event = snmp.send(pdu, snmp_target)
        response_pdu = response_event.response
        response_array = []
        response_array = pdu_to_ruby_array(response_pdu) unless response_pdu.nil?
        # timeout
        if response_pdu.nil?
          finished = true
          # nontimeout error
        elsif response_pdu.error_status != 0
          finished = true
          # returned no oids but was not an error (end of tree?)
        elsif response_array.length == 0
          finished = true
          # lexical compare, are we done with the tree?
        elsif !response_array.last.oid.starts_with(snmp_oid)
          finished = true
        end
        if (response_array.length > 0)
          # only add results that match filter
          @result += response_array.select { |vb| vb.oid.starts_with(snmp_oid) }
          # start next poll with last oid from
          self.oids = [response_array.last.oid.to_s]
        end
      end
      @pdus_sent -= 1
      snmp.close
      @result
    end

    def walk_interfaces
      walk('1.3.6.1.2.1.2')
    end

    def walk_ifX
      walk('1.3.6.1.2.1.31')
    end

    def walk_full_interfaces
      output = walk_interfaces
      output += walk_ifX
      @result = output
    end

    def walk_system
      walk('1.3.6.1.2.1.1')
    end

    def walk_volumes
      walk('1.3.6.1.2.1.25.3.8')
    end

    def walk_resources
      walk('1.3.6.1.2.1.25.2.3.1')
    end

    def walk_software
      walk('1.3.6.1.2.1.25.6.3.1')
    end

    def walk_processes
      walk('1.3.6.1.2.1.25.4.2.1')
    end

    def nonblocking_walk(oid = nil)
    end

    def send(callback = nil)
      callback = self if callback.nil?
      @result = []
      snmp.listen
      snmp.send(pdu, snmp_target, self, callback)
      snmp.close
      @pdus_sent += 1
    end

    def onResponse(event)
      event.source.cancel(event.request, self)
      @result << {:target => event.user_object, :request => event.request, :response => event.response, :event => event}
      @pdus_sent -= 1
    end

    def poll_complete?(blocking = true)
      if blocking
        loop do
          return true if @pdus_sent == 0
          sleep 0.1
        end
      else
        if @pdus_sent == 0
          true
        else
          false
        end
      end
    end

    def result_to_s
      output = ''
      @result.each do |res|
        output += (res.to_s + "\n") if res.class == Java::OrgSnmp4jSmi::VariableBinding
        if res.class == Array
          res.each do |hash_event|
            hash_event.response.variable_bindings.each do |vb|
              output += (vb.to_s + "\n")
            end
          end
        end
      end
      output
    end

    def pdu
      @pdu = version_3? ? Snmp4JR::ScopedPDU.new : Snmp4JR::PDU.new
      @oids.each do |oid|
        @pdu.add(Snmp4JR::SMI::VariableBinding.new(Snmp4JR::SMI::OID.new(oid)))
      end
      @pdu.max_repetitions = @max_repetitions
      @pdu.non_repeaters = @non_repeaters
      @pdu.type = @request_type
      @pdu
    end

    def version_3?
      @version == Snmp4JR::MP::Version3
    end

    def credentials_received?
      @username && @auth_password && @priv_password
    end

    def authenticated?
      version_3? && credentials_received?
    end

    private

    def reset_session
      @pdu = nil unless @oids.nil?
      @snmp_target = nil
      @result = []
      @pdus_sent = 0
    end

    def pdu_to_ruby_array(ipdu)
      iresult = []
      ipdu.variable_bindings.each do |vb|
        iresult << vb
      end
      iresult
    end
  end
end
