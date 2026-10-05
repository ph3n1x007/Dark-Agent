require "./proxy_config_spec"
require "../src/dark/common/logger"
require "../src/dark/elf/*"
require "../src/dark/agent/transport"

class ProxyTestTransport < Dark::Agent::Transport::Base
  def request(url : String, headers = HTTP::Headers.new, body = "lab-body", method = "POST")
    send_http_request(url, headers, body, method)
  end

  def process_response(raw_body : String) : String
    raw_body
  end

  def send_request(message : String) : {HTTP::Client::Response?, String?}
    {nil, nil}
  end
end

def with_lab_proxy(args = [] of String, &)
  fixture = File.join(__DIR__, "support", "proxy_lab.py")
  process = Process.new("python3", [fixture] + args, output: :pipe, error: STDERR)
  begin
    port = process.output.gets.not_nil!.to_i
    yield process, port
  ensure
    unless process.terminated?
      process.terminate
      process.wait
    end
  end
end

def lab_stats(process : Process)
  stats = JSON.parse(process.output.gets.not_nil!)
  process.wait.success?.should be_true
  stats
end

describe "Proxy transport" do
  {false, true}.each do |tls|
    {false, true}.each do |environment|
      it "uses a local proxy without auth for #{tls ? "HTTPS" : "HTTP"} from #{environment ? "env" : "profile"}" do
        with_lab_proxy(tls ? ["--tls"] : [] of String) do |process, port|
          env = environment ? {(tls ? "https_proxy" : "http_proxy") => "http://127.0.0.1:#{port}"} : {} of String => String
          with_proxy_env(env) do
            config = environment ? proxy_test_config("{}", %({"ssl_verify":false})) : proxy_test_config(%({"proxy_host":"http://127.0.0.1:#{port}"}), %({"ssl_verify":false}))
            url = tls ? "https://origin.test:8443/test?q=1" : "http://origin.test:8080/test?q=1"
            headers = HTTP::Headers{"Proxy-Authorization" => "must-be-removed"}
            response, body = ProxyTestTransport.new(config).request(url, headers, "lab-body", "PUT")
            response.not_nil!.status_code.should eq(200)
            body.should eq("proxy-ok")
            headers["Proxy-Authorization"].should eq("must-be-removed")
            stats = lab_stats(process)
            request = tls ? stats["origin"] : stats["requests"][0]
            request["line"].as_s.should eq(tls ? "PUT /test?q=1 HTTP/1.1" : "PUT #{url} HTTP/1.1")
            request["headers"]["host"].as_s.should eq(tls ? "origin.test:8443" : "origin.test:8080")
            request["body"].as_s.should eq("lab-body")
          end
        end
      end
    end

    it "uses decoded Basic credentials for #{tls ? "HTTPS CONNECT" : "HTTP"}" do
      with_lab_proxy(["--auth", "basic"] + (tls ? ["--tls"] : [] of String)) do |process, port|
        with_proxy_env({(tls ? "https_proxy" : "http_proxy") => "http://lab:p%3Ass@127.0.0.1:#{port}"}) do
          config = proxy_test_config("{}", %({"ssl_verify":false}))
          response, body = ProxyTestTransport.new(config).request(tls ? "https://origin.test:8443/test" : "http://origin.test/test")
          response.not_nil!.status_code.should eq(200)
          body.should eq("proxy-ok")
          lab_stats(process)["connections"].as_i.should eq(1)
        end
      end
    end
  end

  if ENV["DARK_AGENT_KERBEROS_TEST"]? == "1"
    {false, true}.each do |tls|
      {"fixed", "chunked"}.each do |framing|
        it "automatically negotiates real Kerberos for #{tls ? "CONNECT" : "HTTP"} with #{framing} 407 framing" do
          args = ["--auth", "negotiate", "--framing", framing, "--status", "201"]
          args << "--tls" if tls
          with_lab_proxy(args) do |process, port|
            with_proxy_env({(tls ? "https_proxy" : "http_proxy") => "http://localhost:#{port}"}) do
              config = proxy_test_config("{}", %({"ssl_verify":false}))
              response, body = ProxyTestTransport.new(config).request(tls ? "https://origin.test:8443/test" : "http://origin.test/test")
              response.not_nil!.status_code.should eq(201)
              body.should eq("proxy-ok")
              stats = lab_stats(process)
              stats["connections"].as_i.should eq(1)
              stats["requests"].as_a.size.should eq(2)
              stats["requests"][0]["headers"]["proxy-authorization"]?.should be_nil
              stats["requests"][1]["headers"]["proxy-authorization"].as_s.should start_with("Negotiate ")
            end
          end
        end
      end

      {"--bad-final", "--missing-final"}.each do |failure|
        it "rejects #{failure} Kerberos server proof for #{tls ? "CONNECT" : "HTTP"}" do
          args = ["--auth", "negotiate", failure]
          args << "--tls" if tls
          with_lab_proxy(args) do |process, port|
            with_proxy_env({(tls ? "https_proxy" : "http_proxy") => "http://localhost:#{port}"}) do
              config = proxy_test_config("{}", %({"ssl_verify":false}))
              response, body = ProxyTestTransport.new(config).request(tls ? "https://origin.test:8443/test" : "http://origin.test/test")
              response.should be_nil
              body.should be_nil
              lab_stats(process)
            end
          end
        end
      end

      it "reconnects when a Kerberos proxy explicitly closes its first 407" do
        args = ["--auth", "negotiate", "--close-first"]
        args << "--tls" if tls
        with_lab_proxy(args) do |process, port|
          with_proxy_env({(tls ? "https_proxy" : "http_proxy") => "http://localhost:#{port}"}) do
            config = proxy_test_config("{}", %({"ssl_verify":false}))
            response, body = ProxyTestTransport.new(config).request(tls ? "https://origin.test:8443/test" : "http://origin.test/test")
            response.not_nil!.status_code.should eq(200)
            body.should eq("proxy-ok")
            lab_stats(process)["connections"].as_i.should eq(2)
          end
        end
      end

      it "fails cleanly if Kerberos is required but the credential cache is missing" do
        args = ["--auth", "negotiate"]
        args << "--tls" if tls
        with_lab_proxy(args) do |process, port|
          with_proxy_env({(tls ? "https_proxy" : "http_proxy") => "http://localhost:#{port}"}) do
            saved_cache = ENV["KRB5CCNAME"]?
            ENV["KRB5CCNAME"] = "FILE:/tmp/dark-proxy-missing-cache-#{Process.pid}"
            begin
              config = proxy_test_config("{}", %({"ssl_verify":false}))
              response, body = ProxyTestTransport.new(config).request(tls ? "https://origin.test:8443/test" : "http://origin.test/test")
              response.should be_nil
              body.should be_nil
              lab_stats(process)["requests"].as_a.size.should eq(1)
            ensure
              if saved_cache
                ENV["KRB5CCNAME"] = saved_cache
              else
                ENV.delete("KRB5CCNAME")
              end
            end
          end
        end
      end
    end
  end
end
