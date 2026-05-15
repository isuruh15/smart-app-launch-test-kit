require 'openssl'

# Trusts locally exported WSO2 certificates for all outbound SSL connections.
# Patches OpenSSL::X509::Store#set_default_paths so every SSL client
# (Net::HTTP, Faraday, tls_test_kit, etc.) automatically trusts these certs.
# Must be loaded before any SSL connections are made (i.e. before 'inferno').
_trusted_certs = %w[config/wso2is.crt config/wso2apim.crt]
  .map { |p| File.expand_path(p, File.join(__dir__, '..')) }
  .select { |p| File.exist?(p) }

unless _trusted_certs.empty?
  OpenSSL::X509::Store.prepend(Module.new do
    define_method(:set_default_paths) do |*args|
      super(*args)
      _trusted_certs.each { |cert| add_file(cert) rescue nil }
    end
  end)
end
