defmodule ExDTLS.BundlexProject do
  use Bundlex.Project

  def project do
    [
      natives: natives()
    ]
  end

  defp natives() do
    [
      native: [
        sources: ["native.c", "dtls.c", "dyn_buff.c", "bio_frag.c"],
        deps: [unifex: :unifex],
        os_deps: [openssl: :pkg_config],
        libs: ["pthread"],
        interface: [:nif],
        # compiler_flags: ["-DEXDTLS_DEBUG"],
        preprocessor: Unifex
      ]
    ]
  end
end
