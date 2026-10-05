require "uri"
require "socket"
require "../config/base"

module Dark::Agent::Transport
  record ProxyInfo, host : String, port : Int32, user : String = "", pass : String = "",
    auth_scheme : String = "", spn_override : String = ""

  module ProxyConfig
    # Explicit profile settings win. Otherwise use the process's inherited environment.
    def self.resolve(uri : URI, config : Config::Base) : ProxyInfo?
      if config.proxy_configured?
        proxy = parse(config.proxy_host, config.proxy_auth_scheme, config.proxy_spn_override)
        port = config.proxy_port.strip
        port_number = port.empty? ? proxy.port : port.to_i?
        raise "Invalid profile proxy port" unless port_number && (1..65535).includes?(port_number)
        user = config.proxy_user.empty? ? proxy.user : config.proxy_user
        pass = config.proxy_user.empty? ? proxy.pass : config.proxy_pass
        return ProxyInfo.new(proxy.host, port_number, user, pass, proxy.auth_scheme, proxy.spn_override)
      end

      return nil if bypass?(uri, ENV["no_proxy"]? || ENV["NO_PROXY"]? || "")
      keys = uri.scheme == "https" ? {"https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"} : {"http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"}
      keys.each do |key|
        if value = ENV[key]?.try(&.strip)
          next if value.empty?
          begin
            return parse(value, config.proxy_auth_scheme, config.proxy_spn_override)
          rescue
            # Do not include the URL here: it may contain a password.
            raise "Invalid or unsupported proxy in #{key}; expected an HTTP proxy host or URL"
          end
        end
      end
      nil
    end

    def self.parse(value : String, scheme : String = "", spn : String = "") : ProxyInfo
      value = value.strip
      url = value.includes?("://") ? value : "http://#{value}"
      parts = /\A([^:]+):\/\/([^\/?#]*)(.*)\z/m.match(url) || raise "Invalid proxy URL"
      authority = parts[2]
      user = pass = ""
      if delimiter = authority.rindex('@')
        # Parse userinfo ourselves: Crystal's URI parser treats '+' as a space
        # and splits again at each ':'. Decode URL credentials exactly once.
        credentials = authority[0...delimiter].split(':', 2)
        user = URI.decode(credentials[0], plus_to_space: false)
        pass = URI.decode(credentials[1]? || "", plus_to_space: false)
        authority = authority[delimiter + 1..]
      end
      uri = URI.parse("#{parts[1]}://#{authority}#{parts[3]}")
      raise "Only HTTP upstream proxies are supported" unless uri.scheme.try(&.downcase) == "http"
      host = uri.hostname
      raise "Invalid proxy host" unless host && !host.empty? && !host.matches?(/[\s\x00-\x1f]/)
      raise "Proxy URL must not have a path, query, or fragment" unless (uri.path.empty? || uri.path == "/") && uri.query.nil? && uri.fragment.nil?
      port = uri.port || 80
      raise "Invalid proxy port" unless (1..65535).includes?(port)
      ProxyInfo.new(host, port, user, pass, scheme, spn)
    end

    # Match domains, IP literals, optional ports, and IPv4/IPv6 CIDR ranges.
    def self.bypass?(uri : URI, exclusions : String) : Bool
      host = uri.hostname.try(&.downcase.rstrip('.')) || ""
      port = uri.port || (uri.scheme == "https" ? 443 : 80)
      exclusions.split(',').any? do |entry|
        entry = entry.strip.downcase
        next false if entry.empty?
        next true if entry == "*"
        if entry.includes?('/')
          next cidr_match?(host, entry)
        end
        if match = /\A\[([^\]]+)\](?::(\d+))?\z/.match(entry)
          entry = match[1]
          next false if match[2]? && match[2].to_i? != port
        elsif entry.count(':') == 1
          name, entry_port = entry.split(':', 2)
          next false unless entry_port.to_i? == port
          entry = name
        end
        entry = entry.lstrip('.').rstrip('.')
        next false if entry.empty?
        if Socket::IPAddress.valid?(host) || Socket::IPAddress.valid?(entry)
          next false unless Socket::IPAddress.valid?(host) && Socket::IPAddress.valid?(entry)
          Socket::IPAddress.new(host, 0).address == Socket::IPAddress.new(entry, 0).address
        else
          host == entry || host.ends_with?(".#{entry}")
        end
      end
    end

    private def self.cidr_match?(host : String, entry : String) : Bool
      network, prefix = entry.split('/', 2)
      bits = prefix.to_i?
      return false unless bits
      if address = Socket::IPAddress.parse_v4_fields?(host)
        subnet = Socket::IPAddress.parse_v4_fields?(network)
        return false unless subnet && (0..32).includes?(bits)
        prefix_match?(address, subnet, bits, 8)
      elsif address = Socket::IPAddress.parse_v6_fields?(host)
        subnet = Socket::IPAddress.parse_v6_fields?(network)
        return false unless subnet && (0..128).includes?(bits)
        prefix_match?(address, subnet, bits, 16)
      else
        false
      end
    end

    private def self.prefix_match?(address, subnet, bits : Int32, width : Int32) : Bool
      address.each_with_index do |field, index|
        break if bits == 0
        used = Math.min(bits, width)
        mask = UInt32::MAX << (width - used)
        return false unless (field.to_u32 & mask) == (subnet[index].to_u32 & mask)
        bits -= used
      end
      true
    end
  end
end
