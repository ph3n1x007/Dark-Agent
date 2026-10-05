require "spec"
require "../src/dark/agent/config"
require "../src/dark/agent/config/http"
require "../src/dark/agent/config/httpx"
require "../src/dark/agent/transport/proxy_config"
require "../src/dark/agent/transport/proxy_auth"

PROXY_ENV_KEYS = %w(http_proxy HTTP_PROXY https_proxy HTTPS_PROXY all_proxy ALL_PROXY no_proxy NO_PROXY)

def with_proxy_env(values = {} of String => String, &)
  saved = PROXY_ENV_KEYS.to_h { |key| {key, ENV[key]?} }
  PROXY_ENV_KEYS.each { |key| ENV.delete(key) }
  values.each { |key, value| ENV[key] = value }
  begin
    yield
  ensure
    saved.each do |key, value|
      if value
        ENV[key] = value
      else
        ENV.delete(key)
      end
    end
  end
end

def proxy_test_config(c2 = "{}", agent = "{}")
  Dark::Agent::Config::Active.new(JSON.parse(%({"agent":#{agent},"c2":#{c2}})))
end

alias ProxySettings = Dark::Agent::Transport::ProxyConfig

describe ProxySettings do
  %w(http_proxy HTTP_PROXY all_proxy ALL_PROXY).each do |key|
    it "discovers #{key} for HTTP" do
      with_proxy_env({key => "http://127.0.0.1:3128"}) do
        proxy = ProxySettings.resolve(URI.parse("http://example.test"), proxy_test_config).not_nil!
        {proxy.host, proxy.port, proxy.user}.should eq({"127.0.0.1", 3128, ""})
      end
    end
  end

  %w(https_proxy HTTPS_PROXY all_proxy ALL_PROXY).each do |key|
    it "discovers #{key} for HTTPS" do
      with_proxy_env({key => "http://localhost:8080"}) do
        ProxySettings.resolve(URI.parse("https://example.test"), proxy_test_config).not_nil!.port.should eq(8080)
      end
    end
  end

  it "picks lowercase and the target scheme before ALL_PROXY" do
    with_proxy_env({"http_proxy" => "lower:8001", "HTTP_PROXY" => "upper:8002", "https_proxy" => "secure:8003", "ALL_PROXY" => "fallback:8004"}) do
      ProxySettings.resolve(URI.parse("http://example.test"), proxy_test_config).not_nil!.host.should eq("lower")
      ProxySettings.resolve(URI.parse("https://example.test"), proxy_test_config).not_nil!.host.should eq("secure")
    end
  end

  it "does not use an HTTP-only env setting for HTTPS" do
    with_proxy_env({"http_proxy" => "local:3128"}) do
      ProxySettings.resolve(URI.parse("https://example.test"), proxy_test_config).should be_nil
    end
  end

  it "uses no proxy when the env is empty" do
    with_proxy_env do
      ProxySettings.resolve(URI.parse("http://example.test"), proxy_test_config).should be_nil
    end
  end

  it "decodes URL credentials and uses port 80 when omitted" do
    proxy = ProxySettings.parse("http://lab%40user:p%3Ass+word@proxy.test")
    {proxy.port, proxy.user, proxy.pass}.should eq({80, "lab@user", "p:ss+word"})
  end

  it "accepts an IPv6 local proxy" do
    proxy = ProxySettings.parse("[::1]:3128")
    {proxy.host, proxy.port}.should eq({"::1", 3128})
  end

  it "decodes percent escapes exactly once" do
    proxy = ProxySettings.parse("http://lab%2540user:p%252F%2B@localhost:3128")
    {proxy.user, proxy.pass}.should eq({"lab%40user", "p%2F+"})
  end

  it "preserves colons and plus signs in URL passwords" do
    proxy = ProxySettings.parse("http://lab:p:ss+word@localhost:3128")
    {proxy.user, proxy.pass}.should eq({"lab", "p:ss+word"})
  end

  it "gives the explicit profile priority over the env and NO_PROXY" do
    with_proxy_env({"http_proxy" => "other:3128", "NO_PROXY" => "*"}) do
      config = proxy_test_config(%({"proxy_host":"http://127.0.0.1:8080","proxy_port":8888}))
      proxy = ProxySettings.resolve(URI.parse("http://example.test"), config).not_nil!
      {proxy.host, proxy.port}.should eq({"127.0.0.1", 8888})
    end
  end

  it "rejects malformed explicit ports" do
    config = proxy_test_config(%({"proxy_host":"localhost","proxy_port":"oops"}))
    expect_raises(Exception, "Invalid profile proxy port") do
      ProxySettings.resolve(URI.parse("http://example.test"), config)
    end
  end

  it "reports an invalid env proxy instead of silently going direct" do
    with_proxy_env({"http_proxy" => "socks5://user:secret@localhost:1080"}) do
      expect_raises(Exception, "Invalid or unsupported proxy in http_proxy") do
        ProxySettings.resolve(URI.parse("http://example.test"), proxy_test_config)
      end
    end
  end

  %w(http://localhost:0 http://localhost:65536 https://localhost:3128 http://localhost/path).each do |value|
    it "rejects #{value}" do
      expect_raises(Exception) { ProxySettings.parse(value) }
    end
  end

  {"no_proxy", "NO_PROXY"}.each do |key|
    it "honors #{key}" do
      with_proxy_env({"http_proxy" => "localhost:3128", key => "example.test"}) do
        ProxySettings.resolve(URI.parse("http://sub.example.test"), proxy_test_config).should be_nil
      end
    end
  end

  {
    {"http://sub.example.test", ".EXAMPLE.test", true},
    {"http://notexample.test", "example.test", false},
    {"http://example.test.evil", "example.test", false},
    {"http://example.test:8080", "example.test:8080", true},
    {"http://example.test:8081", "example.test:8080", false},
    {"http://127.0.0.1", "127.0.0.0/8", true},
    {"http://128.0.0.1", "127.0.0.0/8", false},
    {"http://[::1]:8080", "[::1]:8080", true},
    {"http://[::1]", "0:0:0:0:0:0:0:1", true},
    {"http://[fd00::1]", "fd00::/8", true},
    {"http://[fe00::1]", "fd00::/8", false},
    {"http://example.test", "*", true},
    {"http://example.test", " , ", false},
  }.each do |url, exclusions, matches|
    it "matches #{url} against #{exclusions.inspect}" do
      ProxySettings.bypass?(URI.parse(url), exclusions).should eq(matches)
    end
  end
end

describe Dark::Agent::Transport::NegotiateProxyAuth do
  it "recognizes only an exact Negotiate scheme" do
    auth = Dark::Agent::Transport::NegotiateProxyAuth
    auth.challenge?("Basic realm=\"lab\", nEgOtIaTe").should be_true
    auth.challenge?("Basic realm=\"negotiate\"").should be_false
    auth.challenge?("NegotiateOther").should be_false
    auth.challenge_value("Negotiate dG9rZW4=").should eq("dG9rZW4=")
  end

  it "does not try Kerberos before an auto proxy asks for auth" do
    Dark::Agent::Transport.build_authenticator("", "", "", "127.0.0.1", "").should be_nil
  end
end
