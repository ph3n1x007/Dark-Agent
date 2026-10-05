require "../../common/libc"
require "../../common/logger"

# Runtime binding to libgssapi_krb5.so.2 loaded via dlopen so the agent
# still runs on hosts without Kerberos. Linux-only; macOS stubs out.
module Dark::Agent::Gssapi
  {% if flag?(:linux) %}
    @[Link(ldflags: "-ldl")]
    lib LibDl
      RTLD_NOW   = 0x00002
      RTLD_LOCAL = 0x00000
      fun dlopen(filename : LibC::Char*, flag : LibC::Int) : Void*
      fun dlsym(handle : Void*, symbol : LibC::Char*) : Void*
      fun dlerror : LibC::Char*
      fun dlclose(handle : Void*) : LibC::Int
    end

    # Struct/const-only lib block; no functions (we resolve them via dlsym).
    lib LibGss
      alias OM_uint32 = UInt32

      struct BufferDesc
        length : LibC::SizeT
        value : Void*
      end

      struct OidDesc
        length : OM_uint32
        elements : Void*
      end

      GSS_S_COMPLETE        =           0_u32
      GSS_S_CONTINUE_NEEDED =           1_u32
      GSS_C_MUTUAL_FLAG     = 0x0000_0002_u32
    end

    # SPNEGO mech OID (1.3.6.1.5.5.2) — DER value bytes only.
    SPNEGO_OID_BYTES = Bytes[0x2b_u8, 0x06_u8, 0x01_u8, 0x05_u8, 0x05_u8, 0x02_u8]
    # GSS_C_NT_HOSTBASED_SERVICE (1.2.840.113554.1.2.1.4) — DER value bytes.
    HOSTBASED_OID_BYTES = Bytes[0x2a_u8, 0x86_u8, 0x48_u8, 0x86_u8, 0xf7_u8,
      0x12_u8, 0x01_u8, 0x02_u8, 0x01_u8, 0x04_u8]

    @@loaded = false
    @@load_lock = Mutex.new
    @@handle : Void* = Pointer(Void).null

    @@fn_import_name : Void* = Pointer(Void).null
    @@fn_release_name : Void* = Pointer(Void).null
    @@fn_release_buffer : Void* = Pointer(Void).null
    @@fn_init_sec_context : Void* = Pointer(Void).null
    @@fn_delete_sec_context : Void* = Pointer(Void).null

    def self.available? : Bool
      @@load_lock.synchronize do
        load unless @@loaded
        !@@handle.null?
      end
    end

    private def self.load
      handle = LibDl.dlopen("libgssapi_krb5.so.2", LibDl::RTLD_NOW | LibDl::RTLD_LOCAL)
      if handle.null?
        err = LibDl.dlerror
        log_debug("libgssapi_krb5.so.2 not available: #{err.null? ? "(no dlerror)" : String.new(err)}")
        return
      end
      @@handle = handle
      @@fn_import_name = LibDl.dlsym(handle, "gss_import_name")
      @@fn_release_name = LibDl.dlsym(handle, "gss_release_name")
      @@fn_release_buffer = LibDl.dlsym(handle, "gss_release_buffer")
      @@fn_init_sec_context = LibDl.dlsym(handle, "gss_init_sec_context")
      @@fn_delete_sec_context = LibDl.dlsym(handle, "gss_delete_sec_context")

      if @@fn_import_name.null? || @@fn_init_sec_context.null? ||
         @@fn_release_buffer.null? || @@fn_delete_sec_context.null? ||
         @@fn_release_name.null?
        log_error("libgssapi_krb5.so.2 loaded but a required symbol is missing")
        LibDl.dlclose(handle)
        @@handle = Pointer(Void).null
      else
        log_debug("libgssapi_krb5.so.2 loaded")
      end
    ensure
      @@loaded = true
    end

    # --- Typed proc wrappers over the dlsym'd function pointers ---

    def self.import_name(minor : LibGss::OM_uint32*, buf : LibGss::BufferDesc*,
                         oid : LibGss::OidDesc*, name_out : Void**) : LibGss::OM_uint32
      Proc(LibGss::OM_uint32*, LibGss::BufferDesc*, LibGss::OidDesc*, Void**, LibGss::OM_uint32).new(
        @@fn_import_name, Pointer(Void).null
      ).call(minor, buf, oid, name_out)
    end

    def self.init_sec_context(minor, cred, ctx, target, mech, req_flags, time_req,
                              chan, input, actual_mech, output, ret_flags, time_rec)
      Proc(LibGss::OM_uint32*, Void*, Void**, Void*, LibGss::OidDesc*,
           LibGss::OM_uint32, LibGss::OM_uint32, Void*, LibGss::BufferDesc*,
           LibGss::OidDesc**, LibGss::BufferDesc*, LibGss::OM_uint32*, LibGss::OM_uint32*,
           LibGss::OM_uint32).new(@@fn_init_sec_context, Pointer(Void).null).call(
        minor, cred, ctx, target, mech, req_flags, time_req, chan, input, actual_mech,
        output, ret_flags, time_rec
      )
    end

    def self.release_name(minor : LibGss::OM_uint32*, name : Void**)
      Proc(LibGss::OM_uint32*, Void**, LibGss::OM_uint32).new(
        @@fn_release_name, Pointer(Void).null
      ).call(minor, name)
    end

    def self.release_buffer(minor : LibGss::OM_uint32*, buf : LibGss::BufferDesc*)
      Proc(LibGss::OM_uint32*, LibGss::BufferDesc*, LibGss::OM_uint32).new(
        @@fn_release_buffer, Pointer(Void).null
      ).call(minor, buf)
    end

    def self.delete_sec_context(minor : LibGss::OM_uint32*, ctx : Void**,
                                out_token : LibGss::BufferDesc*)
      Proc(LibGss::OM_uint32*, Void**, LibGss::BufferDesc*, LibGss::OM_uint32).new(
        @@fn_delete_sec_context, Pointer(Void).null
      ).call(minor, ctx, out_token)
    end

    # --- High-level context ---
    class Context
      @name : Void* = Pointer(Void).null
      @ctx : Void* = Pointer(Void).null
      @complete : Bool = false

      getter? complete : Bool

      def initialize(target_spn : String)
        raise "libgssapi_krb5.so.2 not available" unless Gssapi.available?
        import_target(target_spn)
      end

      private def import_target(spn : String)
        minor : LibGss::OM_uint32 = 0_u32
        spn_bytes = spn.to_slice

        buf = LibGss::BufferDesc.new
        buf.length = spn_bytes.size.to_u64
        buf.value = spn_bytes.to_unsafe.as(Void*)

        oid = LibGss::OidDesc.new
        oid.length = HOSTBASED_OID_BYTES.size.to_u32
        oid.elements = HOSTBASED_OID_BYTES.to_unsafe.as(Void*)

        name_out : Void* = Pointer(Void).null
        major = Gssapi.import_name(pointerof(minor), pointerof(buf), pointerof(oid), pointerof(name_out))
        unless major == LibGss::GSS_S_COMPLETE
          raise "gss_import_name failed (major=0x#{major.to_s(16)}, minor=0x#{minor.to_s(16)})"
        end
        @name = name_out
      end

      # Feed a server token in (or nil on the first call); returns the next
      # token to send and whether the exchange is complete.
      def step(input_token : Bytes?) : Tuple(Bytes?, Bool)
        minor : LibGss::OM_uint32 = 0_u32

        mech = LibGss::OidDesc.new
        mech.length = SPNEGO_OID_BYTES.size.to_u32
        mech.elements = SPNEGO_OID_BYTES.to_unsafe.as(Void*)

        input_buf = LibGss::BufferDesc.new
        input_buf.length = 0_u64
        input_buf.value = Pointer(Void).null
        input_ptr : LibGss::BufferDesc* = Pointer(LibGss::BufferDesc).null
        if tok = input_token
          input_buf.length = tok.size.to_u64
          input_buf.value = tok.to_unsafe.as(Void*)
          input_ptr = pointerof(input_buf)
        end

        output_buf = LibGss::BufferDesc.new
        output_buf.length = 0_u64
        output_buf.value = Pointer(Void).null

        ret_flags : LibGss::OM_uint32 = 0_u32
        time_rec : LibGss::OM_uint32 = 0_u32

        begin
          major = Gssapi.init_sec_context(
            pointerof(minor),
            Pointer(Void).null, # GSS_C_NO_CREDENTIAL — default ccache
            pointerof(@ctx),
            @name,
            pointerof(mech),
            LibGss::GSS_C_MUTUAL_FLAG,
            0_u32,              # default lifetime
            Pointer(Void).null, # no channel bindings
            input_ptr,
            Pointer(LibGss::OidDesc*).null,
            pointerof(output_buf),
            pointerof(ret_flags),
            pointerof(time_rec),
          )

          unless major == LibGss::GSS_S_COMPLETE || major == LibGss::GSS_S_CONTINUE_NEEDED
            raise "gss_init_sec_context failed (major=0x#{major.to_s(16)}, minor=0x#{minor.to_s(16)})"
          end

          @complete = (major == LibGss::GSS_S_COMPLETE)
          if @complete && (ret_flags & LibGss::GSS_C_MUTUAL_FLAG) == 0
            raise "Proxy Negotiate did not provide mutual authentication"
          end

          out_bytes : Bytes? = nil
          unless output_buf.value.null?
            # Copy the token before releasing the GSS buffer.
            if output_buf.length > 0
              out_bytes = Bytes.new(output_buf.length.to_i32)
              LibC.memcpy(out_bytes.to_unsafe.as(Void*), output_buf.value, output_buf.length.to_i64)
            end
          end

          {out_bytes, @complete}
        ensure
          if !output_buf.value.null?
            release_minor = 0_u32
            Gssapi.release_buffer(pointerof(release_minor), pointerof(output_buf))
          end
        end
      end

      def dispose
        minor : LibGss::OM_uint32 = 0_u32
        unless @ctx.null?
          Gssapi.delete_sec_context(pointerof(minor), pointerof(@ctx), Pointer(LibGss::BufferDesc).null)
          @ctx = Pointer(Void).null
        end
        unless @name.null?
          Gssapi.release_name(pointerof(minor), pointerof(@name))
          @name = Pointer(Void).null
        end
      end

      def finalize
        dispose
      end
    end
  {% else %}
    # macOS / other: no runtime binding; treat as unavailable.
    def self.available? : Bool
      false
    end

    class Context
      def initialize(target_spn : String)
        raise "Kerberos proxy auth not supported on this platform"
      end

      def step(input_token : Bytes?) : Tuple(Bytes?, Bool)
        raise "Kerberos proxy auth not supported on this platform"
      end

      def dispose; end

      def complete? : Bool
        false
      end
    end
  {% end %}
end
