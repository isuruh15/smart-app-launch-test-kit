require 'openssl'

# Trusts locally exported WSO2 certificates for all outbound SSL connections.
# Must be loaded before any SSL connections are made (i.e. before 'inferno').
#
# Two patches are applied:
#   1. OpenSSL::X509::Store#set_default_paths — covers Faraday and any client
#      that explicitly calls set_default_paths.
#   2. OpenSSL::SSL::SSLContext#set_params — covers Net::HTTP, which initialises
#      its store via set_params without calling set_default_paths.
_trusted_certs = %w[config/wso2is.crt config/wso2apim.crt]
  .map { |p| File.expand_path(p, File.join(__dir__, '..')) }
  .select { |p| File.exist?(p) }

unless _trusted_certs.empty?
  # Patch 1: store created with set_default_paths (Faraday, tls_test_kit direct store usage)
  OpenSSL::X509::Store.prepend(Module.new do
    define_method(:set_default_paths) do |*args|
      super(*args)
      _trusted_certs.each { |cert| add_file(cert) rescue nil }
    end
  end)

  # Patch 2: SSLContext#set_params — Net::HTTP calls this to configure its context.
  # After the default params are applied we add our certs to the context's cert_store.
  OpenSSL::SSL::SSLContext.prepend(Module.new do
    define_method(:set_params) do |*args|
      result = super(*args)
      _trusted_certs.each { |cert| self.cert_store.add_file(cert) rescue nil } if self.cert_store
      result
    end
  end)
end
