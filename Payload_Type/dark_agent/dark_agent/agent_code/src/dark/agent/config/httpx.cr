require "./base"

module Dark::Agent::Config
  # HTTPX profile configuration handler
  class HTTPX < Base
    def c2_profile : JSON::Any
      if @config["c2"]?
        return @config["c2"]
      end
      JSON.parse("{}")
    end
    
    def payload_uuid : String
      if @config["agent"]? && @config["agent"]["uuid"]?
        return @config["agent"]["uuid"].as_s
      end
      ""
    end
    
    def sleep_interval : Int32
      if @config["c2"]? && @config["c2"]["callback_interval"]?
        return @config["c2"]["callback_interval"].as_i
      end
      5 # Default value
    end
    
    def jitter_percent : Int32
      if @config["c2"]? && @config["c2"]["callback_jitter"]?
        return @config["c2"]["callback_jitter"].as_i
      end
      10 # Default value
    end
    
    def killdate : String
      if @config["c2"]? && @config["c2"]["killdate"]?
        return @config["c2"]["killdate"].as_s
      end
      ""
    end
    
    def encryption_type : String
      if @config["c2"]? && @config["c2"]["AESPSK"]? && @config["c2"]["AESPSK"]["value"]?
        return @config["c2"]["AESPSK"]["value"].as_s
      end
      ""
    end
    
    def encryption_key : String
      if @config["c2"]? && @config["c2"]["AESPSK"]? && @config["c2"]["AESPSK"]["enc_key"]?
        return @config["c2"]["AESPSK"]["enc_key"].as_s
      end
      ""
    end
    
    def decryption_key : String
      if @config["c2"]? && @config["c2"]["AESPSK"]? && @config["c2"]["AESPSK"]["dec_key"]?
        return @config["c2"]["AESPSK"]["dec_key"].as_s
      end
      ""
    end
    
    # Domain rotation strategy
    def domain_rotation : String
      if @config["c2"]? && @config["c2"]["domain_rotation"]?
        return @config["c2"]["domain_rotation"].as_s
      end
      "fail-over" # Default to fail-over strategy
    end
    
    # Failover threshold for domain rotation
    def failover_threshold : Int32
      if @config["c2"]? && @config["c2"]["failover_threshold"]?
        return @config["c2"]["failover_threshold"].as_i
      end
      5 # Default to 5 failed attempts
    end
    
    # Agent config options - these are located directly in the agent section for HTTPX
    def symmetric_jitter? : Bool
      if @config["agent"]? && @config["agent"]["symmetric_jitter"]?
        return @config["agent"]["symmetric_jitter"].as_bool
      end
      false
    end
    
    def chunk_size : Int32
      if @config["agent"]? && @config["agent"]["chunk_size"]?
        return @config["agent"]["chunk_size"].as_i
      end
      512_000 # Default to 512KB
    end
    
    def realtime? : Bool
      if @config["agent"]? && @config["agent"]["realtime"]?
        return @config["agent"]["realtime"].as_bool
      end
      false
    end
    
    
    def ssl_verify? : Bool
      if @config["agent"]? && @config["agent"]["ssl_verify"]?
        return @config["agent"]["ssl_verify"].as_bool
      end
      true # Default to SSL verification enabled for security
    end

    def disable_ssl_verify? : Bool
      !ssl_verify?
    end

    def proxy_host : String
      if @config["c2"]? && @config["c2"]["proxy_host"]?
        return @config["c2"]["proxy_host"].as_s
      end
      ""
    end

    def proxy_port : String
      if @config["c2"]? && (value = @config["c2"]["proxy_port"]?)
        if text = value.as_s?
          return text
        end
        if number = value.as_i?
          return number.to_s
        end
      end
      ""
    end

    def proxy_user : String
      if @config["c2"]? && @config["c2"]["proxy_user"]?
        return @config["c2"]["proxy_user"].as_s
      end
      ""
    end

    def proxy_pass : String
      if @config["c2"]? && @config["c2"]["proxy_pass"]?
        return @config["c2"]["proxy_pass"].as_s
      end
      ""
    end

    def proxy_auth_scheme : String
      if agent = @config["agent"]?
        if value = agent["proxy_auth_scheme"]?
          scheme = value.as_s.strip.downcase
          return scheme unless scheme.empty?
        end
      end
      if @config["c2"]? && @config["c2"]["proxy_auth_scheme"]?
        return @config["c2"]["proxy_auth_scheme"].as_s.strip.downcase
      end
      ""
    end

    def proxy_spn_override : String
      if agent = @config["agent"]?
        if value = agent["proxy_spn_override"]?
          override = value.as_s.strip
          return override unless override.empty?
        end
      end
      if @config["c2"]? && @config["c2"]["proxy_spn_override"]?
        return @config["c2"]["proxy_spn_override"].as_s.strip
      end
      ""
    end
  end
end
