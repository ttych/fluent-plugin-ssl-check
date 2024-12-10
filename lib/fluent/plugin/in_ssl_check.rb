# frozen_string_literal: true

#
# Copyright 2023- Thomas Tych
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'fluent/plugin/input'

require 'socket'
require 'openssl'
require 'timeout'
require 'date'

require_relative 'extensions/time'
require_relative 'ssl_check'

module Fluent
  module Plugin
    class SslCheckInput < Fluent::Plugin::Input
      NAME = 'ssl_check'
      Fluent::Plugin.register_input(NAME, self)

      include Fluent::Plugin::SslCheck::SslInputEmit

      DEFAULT_TAG = NAME
      DEFAULT_PORT = 443
      DEFAULT_INTERVAL = 600
      DEFAULT_SNI = true
      DEFAULT_VERIFY_MODE = :peer
      DEFAULT_TIMEOUT = 5
      DEFAULT_LOG_EVENTS = true
      DEFAULT_METRIC_EVENTS = false
      DEFAULT_EVENT_PREFIX = ''
      DEFAULT_TIMESTAMP_FORMAT = :iso

      desc 'Tag to emit events on'
      config_param :tag, :string, default: DEFAULT_TAG

      desc 'Host of the service to check'
      config_param :hosts, :array, default: [], value_type: :string
      desc 'Interval for the check execution'
      config_param :interval, :time, default: DEFAULT_INTERVAL
      desc 'CA path to load'
      config_param :ca_path, :string, default: nil
      desc 'CA file to load'
      config_param :ca_file, :string, default: nil
      desc 'SNI support'
      config_param :sni, :bool, default: DEFAULT_SNI
      desc 'Verify mode'
      config_param :verify_mode, :enum, list: %i[none peer], default: DEFAULT_VERIFY_MODE
      desc 'Client Cert'
      config_param :cert, :string, default: nil
      desc 'Client Key'
      config_param :key, :string, default: nil

      desc 'Timeout for check'
      config_param :timeout, :integer, default: DEFAULT_TIMEOUT

      desc 'Emit log events'
      config_param :log_events, :bool, default: DEFAULT_LOG_EVENTS
      desc 'Emit metric events'
      config_param :metric_events, :bool, default: DEFAULT_METRIC_EVENTS
      desc 'Event prefix'
      config_param :event_prefix, :string, default: DEFAULT_EVENT_PREFIX
      desc 'Timestamp format'
      config_param :timestamp_format, :enum, list: %i[iso epochmillis], default: DEFAULT_TIMESTAMP_FORMAT

      helpers :timer

      # rubocop:disable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity, Metrics/AbcSize, Style/DoubleNegation
      def configure(conf)
        super

        raise Fluent::ConfigError, 'tag can not be empty.' if !tag || tag.empty?
        raise Fluent::ConfigError, 'hosts can not be empty.' unless hosts
        raise Fluent::ConfigError, 'interval can not be < 1.' if !interval || interval < 1
        raise Fluent::ConfigError, 'ca_path should be a dir.' if ca_path && !File.directory?(ca_path)
        raise Fluent::ConfigError, 'ca_file should be a file.' if ca_file && !File.file?(ca_file)
        raise Fluent::ConfigError, 'cert should be a file.' if cert && !File.file?(cert)
        raise Fluent::ConfigError, 'key should be a file.' if key && !File.file?(key)
        raise Fluent::ConfigError, 'cert and key should be specified.' if !!cert ^ !!key

        log.warn("#{NAME}: hosts is empty, nothing to process") if hosts.empty?
      end
      # rubocop:enable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity, Metrics/AbcSize, Style/DoubleNegation

      def start
        super

        timer_execute(:ssl_check_timer, 1, repeat: false, &method(:check)) if interval > 60

        timer_execute(:ssl_check_timer, interval, repeat: true, &method(:check))
      end

      def check
        hosts.each do |host_full|
          host, port = host_full.split(':')
          port = (port || DEFAULT_PORT).to_i
          ssl_info = fetch_ssl_info(host, port)
          emit_logs(ssl_info) if log_events
          emit_metrics(ssl_info) if metric_events
        rescue StandardError => e
          log.warn "#{NAME}#check: #{e}"
        end
      end

      def fetch_ssl_info(host, port)
        ssl_client = SslClient.new(
          host: host, port: port,
          ca_path: ca_path, ca_file: ca_file,
          sni: sni, verify_mode: ssl_verify_mode,
          cert: cert, key: key,
          timeout: timeout
        )
        ssl_client.ssl_info
      end

      private

      def ssl_verify_mode
        return OpenSSL::SSL::VERIFY_PEER if verify_mode == :peer

        OpenSSL::SSL::VERIFY_NONE
      end

      # ssl client
      #  to check ssl status
      class SslClient
        include Fluent::Plugin::SslCheck::SslCommon

        attr_reader :host, :port, :ca_path, :ca_file, :sni, :verify_mode, :cert, :key, :timeout

        # rubocop:disable Metrics/ParameterLists
        def initialize(host:, port:, ca_path: nil, ca_file: nil, sni: true, verify_mode: OpenSSL::SSL::VERIFY_PEER,
                       cert: nil, key: nil,
                       timeout: 5)
          @host = host
          @port = port
          @ca_path = ca_path
          @ca_file = ca_file
          @sni = sni
          @verify_mode = verify_mode
          @cert = cert
          @key = key
          @timeout = timeout
        end
        # rubocop:enable Metrics/ParameterLists

        def ssl_info
          info = Fluent::Plugin::SslCheck::SslInfo.new(host: host, port: port)
          begin
            Timeout.timeout(timeout) do
              tcp_socket = TCPSocket.open(host, port)
              ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, ssl_context)
              ssl_socket.hostname = host if sni
              ssl_socket.connect
              ssl_socket.sysclose
              tcp_socket.close

              # cert_store.verify(ssl_socket.peer_cert, ssl_socket.peer_cert_chain)
              info.cert = ssl_socket.peer_cert
              info.cert_chain = ssl_socket.peer_cert_chain
              info.ssl_version = ssl_socket.ssl_version
            end
          rescue StandardError => e
            info.error = e
          end
          info
        end

        def ssl_context
          OpenSSL::SSL::SSLContext.new.tap do |ssl_context|
            ssl_context.verify_mode = verify_mode
            ssl_context.cert_store = ssl_store(ca_path: ca_path, ca_file: ca_file)
            ssl_context.min_version = nil
            ssl_context.max_version = OpenSSL::SSL::TLS1_2_VERSION
            ssl_context.cert = OpenSSL::X509::Certificate.new(File.open(cert)) if cert
            ssl_context.key = OpenSSL::PKey::RSA.new(File.open(key)) if key
          end
        end
      end
    end
  end
end
