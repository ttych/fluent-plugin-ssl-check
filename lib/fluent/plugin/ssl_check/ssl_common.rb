# frozen_string_literal: true

require 'openssl'

module Fluent
  module Plugin
    module SslCheck
      module SslCommon
        def ssl_store(ca_path: nil, ca_file: nil)
          OpenSSL::X509::Store.new.tap do |store|
            store.set_default_paths
            store.add_path(ca_path) if ca_path
            store.add_file(ca_file) if ca_file
          end
        end
      end
    end
  end
end
