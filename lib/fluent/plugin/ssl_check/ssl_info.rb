# frozen_string_literal: true

require 'openssl'

module Fluent
  module Plugin
    module SslCheck
      # ssl info
      #  to encapsulate extracted ssl information
      class SslInfo
        OK = 1
        KO = 0

        attr_accessor :host, :port, :path, :cert, :cert_chain, :ssl_version, :error

        # rubocop:disable Metrics/ParameterLists
        def initialize(host: nil, port: nil, path: nil, cert: nil, cert_chain: nil, ssl_version: nil,
                       error: nil, time: nil)
          @host = host
          @port = port
          @path = path
          @cert = cert
          @cert_chain = cert_chain
          @ssl_version = ssl_version
          @error = error
          @time = time
        end
        # rubocop:enable Metrics/ParameterLists

        def subject_s
          cert.subject.to_utf8 if cert&.subject
        end

        def expire_in_days
          return unless cert&.not_after

          expire_in = cert.not_after
          ((expire_in - time) / 3600 / 24).to_i
        end

        def not_after
          return unless cert

          cert.not_after.iso8601(3)
        end

        def serial
          cert&.serial&.to_s(16)&.downcase
        end

        def status
          return KO if error

          OK
        end

        def time
          @time ||= Time.now.utc
        end

        def time_utc
          time.utc
        end

        def error_class
          return unless error

          return error if error.is_a?(String)

          error.class.to_s
        end
      end
    end
  end
end
