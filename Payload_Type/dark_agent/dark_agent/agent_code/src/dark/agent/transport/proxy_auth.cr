require "base64"
require "../../common/logger"
require "./gssapi"

module Dark::Agent::Transport
  # Max Negotiate continuation rounds before giving up.
  PROXY_AUTH_MAX_ROUNDS = 3

  # Build the target SPN for a given proxy host, honouring an operator
  # override. Format is "HTTP@<hostname>" for GSS_C_NT_HOSTBASED_SERVICE.
  # An override uses the same host-based service format.
  def self.build_spn(proxy_host : String, override : String) : String
    return override unless override.empty?
    "HTTP@#{proxy_host}"
  end

  # Base authenticator interface. Concrete strategies produce the
  # Proxy-Authorization header value for each round and consume the
  # server challenge from Proxy-Authenticate on 407s.
  abstract class ProxyAuthenticator
    getter scheme : String

    def initialize(@scheme : String)
    end

    # Initial header value for the first request (may be nil if the
    # scheme is challenge-first, e.g. Basic with no creds).
    abstract def initial_header : String?

    # Feed the value of Proxy-Authenticate from a 407 response; return
    # the next Proxy-Authorization value, or nil if we cannot continue.
    abstract def continue(challenge : String?) : String?

    # True once no further rounds are needed.
    abstract def done? : Bool

    def dispose
    end
  end

  # RFC 7617 Basic proxy auth (existing behaviour, refactored under the
  # authenticator interface).
  class BasicProxyAuth < ProxyAuthenticator
    @user : String
    @pass : String
    @sent : Bool = false

    def initialize(@user : String, @pass : String)
      super("basic")
    end

    def initial_header : String?
      return nil if @user.empty?
      @sent = true
      "Basic " + Base64.strict_encode("#{@user}:#{@pass}")
    end

    def continue(challenge : String?) : String?
      return nil if @sent || @user.empty?
      @sent = true
      "Basic " + Base64.strict_encode("#{@user}:#{@pass}")
    end

    def done? : Bool
      @sent
    end
  end

  # RFC 4559 Negotiate (SPNEGO/Kerberos) proxy auth.
  class NegotiateProxyAuth < ProxyAuthenticator
    @ctx : Dark::Agent::Gssapi::Context?
    @spn : String
    @rounds : Int32 = 0
    @done : Bool = false
    @failed : Bool = false

    def self.challenge?(challenge : String) : Bool
      !challenge_value(challenge).nil?
    end

    def self.challenge_value(challenge : String) : String?
      challenge.split(',').each do |part|
        if match = /\ANegotiate(?:[ \t]+([^\s]+))?\z/i.match(part.strip)
          return match[1]? || ""
        end
      end
      nil
    end

    def initialize(@spn : String)
      super("negotiate")
      @ctx = Dark::Agent::Gssapi::Context.new(@spn)
    end

    # Pre-emptive: build the first token without waiting for a 407.
    def initial_header : String?
      build_next(nil)
    end

    # Feed the server's Negotiate token (base64, from Proxy-Authenticate).
    def continue(challenge : String?) : String?
      token_bytes : Bytes? = nil
      return nil unless raw = challenge
      return nil unless rest = self.class.challenge_value(raw)
      unless rest.empty?
        token_bytes = Base64.decode(rest)
      end
      build_next(token_bytes)
    end

    # Complete mutual auth before accepting a proxy's final response.
    def finish(challenge : String?)
      if challenge && (value = self.class.challenge_value(challenge)) && !value.empty?
        next_header = self.continue(challenge)
        raise "Proxy Negotiate requires another token after its final response" if next_header
      end
      raise "Proxy Negotiate exchange was not completed" unless done?
    end

    def done? : Bool
      @done && !@failed
    end

    def dispose
      if c = @ctx
        c.dispose
        @ctx = nil
      end
    end

    private def build_next(input : Bytes?) : String?
      raise "Proxy Negotiate exchange already failed" if @failed
      return nil if @done && input.nil?
      if @rounds >= PROXY_AUTH_MAX_ROUNDS
        @failed = true
        raise "Proxy Negotiate exceeded #{PROXY_AUTH_MAX_ROUNDS} rounds"
      end
      @rounds += 1

      begin
        ctx = @ctx.not_nil!
        out_token, complete = ctx.step(input)
        @done = complete
        if tok = out_token
          return "Negotiate " + Base64.strict_encode(tok)
        end
        nil
      rescue ex
        @failed = true
        @done = false
        raise ex
      end
    end
  end

  # Factory. Picks a concrete authenticator based on config + creds +
  # runtime library availability.
  #
  # Rules:
  # - explicit scheme "basic"     -> BasicProxyAuth(user,pass)
  # - explicit scheme "negotiate" -> NegotiateProxyAuth(spn)  (may fail if libgssapi missing)
  # - "" (auto):
  #     * if user/pass present     -> Basic
  #     * otherwise                 -> nil until the proxy challenges
  def self.build_authenticator(scheme : String, user : String, pass : String,
                               proxy_host : String, spn_override : String) : ProxyAuthenticator?
    picked = scheme
    if picked.empty?
      picked = user.empty? ? "" : "basic"
    end

    case picked
    when "basic"
      return nil if user.empty?
      BasicProxyAuth.new(user, pass)
    when "negotiate"
      unless Dark::Agent::Gssapi.available?
        log_error("Negotiate requested but libgssapi_krb5.so.2 not available")
        return nil
      end
      spn = Dark::Agent::Transport.build_spn(proxy_host, spn_override)
      begin
        NegotiateProxyAuth.new(spn)
      rescue ex
        log_error("Negotiate init failed: #{ex.message}")
        nil
      end
    else
      nil
    end
  end
end
