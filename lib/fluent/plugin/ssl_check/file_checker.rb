# frozen_string_literal: true

require 'socket'
require 'openssl'
require_relative 'ssl_common'
require_relative 'ssl_info'

module Fluent
  module Plugin
    module SslCheck
      class FileChecker
        attr_reader :filepath, :ca_path, :ca_file

        include Fluent::Plugin::SslCheck::SslCommon

        def initialize(filepath, ca_path: nil, ca_file: nil)
          @filepath = filepath
          @ca_path = ca_path
          @ca_file = ca_file
        end

        def certificate
          @certificate ||= OpenSSL::X509::Certificate.new(File.read(filepath_absolute))
        end

        def filepath_absolute
          File.expand_path(filepath)
        end

        def ssl_info
          info = Fluent::Plugin::SslCheck::SslInfo.new(host: hostname, path: filepath_absolute)
          begin
            ca_store = ssl_store(ca_path: ca_path, ca_file: ca_file)
            ca_store.verify(certificate)

            info.cert = certificate
            info.cert_chain = ca_store.chain
            info.error = ca_store.error_string if ca_store.error != 0
          rescue StandardError => e
            info.error = e
          end
          info
        end

        def hostname
          Socket.gethostname
        end
      end
    end
  end
end
