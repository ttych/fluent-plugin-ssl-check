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

module Fluent
  module Plugin
    # ssl_check input plugin
    #   check ssl service
    class SslCheckInput < Fluent::Plugin::Input
      NAME = 'ssl_check'
      Fluent::Plugin.register_input(NAME, self)

      DEFAULT_TAG = NAME
      DEFAULT_HOST = 'localhost'
      DEFAULT_PORT = 443
      DEFAULT_TIME = 600
      DEFAULT_TIMEOUT = 5
      DEFAULT_LOG_EVENTS = true
      DEFAULT_METRIC_EVENTS = false
      DEFAULT_EVENT_PREFIX = ''

      desc 'Tag to emit events on'
      config_param :tag, :string, default: DEFAULT_TAG

      desc 'Host of the service to check'
      config_param :hosts, :array, default: [], value_type: :string
      desc 'Interval for the check execution'
      config_param :interval, :time, default: DEFAULT_TIME
      desc 'CA path to load'
      config_param :ca_path, :string, default: nil
      desc 'CA file to load'
      config_param :ca_file, :string, default: nil

      desc 'Timeout for check'
      config_param :timeout, :integer, default: DEFAULT_TIMEOUT

      desc 'Emit log events'
      config_param :log_events, :bool, default: DEFAULT_LOG_EVENTS
      desc 'Emit metric events'
      config_param :metric_events, :bool, default: DEFAULT_METRIC_EVENTS
      desc 'Event prefix'
      config_param :event_prefix, :string, default: DEFAULT_EVENT_PREFIX
      desc 'Timestamp format'
      config_param :timestamp_format, :enum, list: %i[iso epochmillis], default: :iso

      helpers :timer

      # rubocop:disable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
      def configure(conf)
        super

        raise Fluent::ConfigError, 'tag can not be empty.' if !tag || tag.empty?
        raise Fluent::ConfigError, 'hosts can not be empty.' if !hosts || hosts.empty?
        raise Fluent::ConfigError, 'interval can not be < 1.' if !interval || interval < 1
        raise Fluent::ConfigError, 'ca_path should be a dir.' if ca_path && !File.directory?(ca_path)
        raise Fluent::ConfigError, 'ca_file should be a file.' if ca_file && !File.file?(ca_file)
      end
      # rubocop:enable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity

      def start
        super

        timer_execute(:ssl_check_timer, interval, repeat: true, &method(:check))
      end

      # rubocop:disable Lint/SuppressedException
      def check
        hosts.each do |host_full|
          host, port = host_full.split(':')
          port = (port || DEFAULT_PORT).to_i
          ssl_info = fetch_ssl_info(host, port)
          emit_logs(ssl_info) if log_events
          emit_metrics(ssl_info) if metric_events
        rescue StandardError
        end
      end
      # rubocop:enable Lint/SuppressedException

      def fetch_ssl_info(host, port)
        ssl_client = SslClient.new(
          host: host, port: port,
          ca_path: ca_path, ca_file: ca_file,
          timeout: timeout
        )
        ssl_client.ssl_info
      end

      def emit_logs(ssl_info)
        record = {
          'timestamp' => ssl_info.time.send("to_#{timestamp_format}"),
          'status' => ssl_info.status,
          'host' => ssl_info.host,
          'port' => ssl_info.port,
          'ssl_version' => ssl_info.ssl_version,
          'ssl_dn' => ssl_info.subject_s,
          'ssl_not_after' => ssl_info.not_after,
          'expire_in_days' => ssl_info.expire_in_days
        }
        record.update('error_class' => ssl_info.error_class) if ssl_info.error_class
        router.emit(tag, Fluent::EventTime.from_time(ssl_info.time), record)
      end

      def emit_metrics(ssl_info)
        emit_metric_status(ssl_info)
        emit_metric_expirency(ssl_info)
      end

      def emit_metric_status(ssl_info)
        record = {
          'timestamp' => ssl_info.time.send("to_#{timestamp_format}"),
          'metric_name' => 'ssl_status',
          'metric_value' => ssl_info.status,
          "#{event_prefix}host" => ssl_info.host,
          "#{event_prefix}port" => ssl_info.port,
          "#{event_prefix}ssl_dn" => ssl_info.subject_s,
          "#{event_prefix}ssl_version" => ssl_info.ssl_version,
          "#{event_prefix}ssl_not_after" => ssl_info.not_after
        }
        router.emit(tag, Fluent::EventTime.from_time(ssl_info.time), record)
      end

      def emit_metric_expirency(ssl_info)
        return if ssl_info.error

        record = {
          'timestamp' => ssl_info.time.send("to_#{timestamp_format}"),
          'metric_name' => 'ssl_expirency',
          'metric_value' => ssl_info.expire_in_days,
          "#{event_prefix}host" => ssl_info.host,
          "#{event_prefix}port" => ssl_info.port,
          "#{event_prefix}ssl_dn" => ssl_info.subject_s
        }
        router.emit(tag, Fluent::EventTime.from_time(ssl_info.time), record)
      end

      # ssl info
      #  to encapsulate extracted ssl information
      class SslInfo
        OK = 1
        KO = 0

        attr_reader :time
        attr_accessor :host, :port, :cert, :cert_chain, :ssl_version, :error

        # rubocop:disable Metrics/ParameterLists
        def initialize(host: nil, port: nil, cert: nil, cert_chain: nil, ssl_version: nil, error: nil, time: Time.now)
          @host = host
          @port = port
          @cert = cert
          @cert_chain = cert_chain
          @ssl_version = ssl_version
          @error = error
          @time = time
        end
        # rubocop:enable Metrics/ParameterLists

        def subject_s
          cert.subject.to_s if cert&.subject
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

        def status
          return KO if error

          OK
        end

        def error_class
          return unless error

          error.class.to_s
        end
      end

      # ssl client
      #  to check ssl status
      class SslClient
        attr_reader :host, :port, :ca_path, :ca_file, :timeout

        def initialize(host:, port:, ca_path: nil, ca_file: nil, timeout: 5)
          @host = host
          @port = port
          @ca_path = ca_path
          @ca_file = ca_file
          @timeout = timeout
        end

        def ssl_info
          info = SslInfo.new(host: host, port: port)
          begin
            Timeout.timeout(timeout) do
              tcp_socket = TCPSocket.open(host, port)
              ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, ssl_context)
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

        def store
          OpenSSL::X509::Store.new.tap do |store|
            store.set_default_paths
            store.add_path(ca_path) if ca_path
            store.add_file(ca_file) if ca_file
          end
        end

        def ssl_context
          OpenSSL::SSL::SSLContext.new.tap do |ssl_context|
            ssl_context.verify_mode = OpenSSL::SSL::VERIFY_PEER
            ssl_context.cert_store = store
            ssl_context.min_version = nil
            ssl_context.max_version = OpenSSL::SSL::TLS1_2_VERSION
          end
        end
      end
    end
  end
end
