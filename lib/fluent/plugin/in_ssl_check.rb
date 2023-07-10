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

      desc 'Tag to emit events on'
      config_param :tag, :string, default: DEFAULT_TAG

      desc 'Host of the service to check'
      config_param :host, :string, default: DEFAULT_HOST
      desc 'Port of the service to check'
      config_param :port, :integer, default: DEFAULT_PORT
      desc 'Interval for the check execution'
      config_param :interval, :time, default: DEFAULT_TIME
      desc 'CA path to load'
      config_param :ca_path, :string, default: nil
      desc 'CA file to load'
      config_param :ca_file, :string, default: nil

      desc 'Timeout for check'
      config_param :timeout, :integer, default: DEFAULT_TIMEOUT

      helpers :timer

      # rubocop:disable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
      def configure(conf)
        super

        raise Fluent::ConfigError, 'tag can not be empty.' if !tag || tag.empty?
        raise Fluent::ConfigError, 'host can not be empty.' if !host || host.empty?
        raise Fluent::ConfigError, 'port can not be < 1' if !port || port < 1
        raise Fluent::ConfigError, 'interval can not be < 1.' if !interval || interval < 1
        raise Fluent::ConfigError, 'ca_path should be a dir.' if ca_path && !File.directory?(ca_path)
        raise Fluent::ConfigError, 'ca_file should be a file.' if ca_file && !File.file?(ca_file)

        @ssl_client = SslClient.new(
          host: host, port: port,
          ca_path: ca_path, ca_file: ca_file,
          timeout: timeout
        )
      end
      # rubocop:enable Metrics/AbcSize, Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity

      def start
        super

        timer_execute(:ssl_check_timer, interval, repeat: true, &method(:check))
      end

      def check
        time = now

        ssl_info = fetch_ssl_info
        router.emit(tag, time, event_status(time, ssl_info))
        router.emit(tag, time, event_expirency(time, ssl_info))
      rescue StandardError
        router.emit(tag, time, event_status_failure(time))
      end

      def fetch_ssl_info
        @ssl_client.ssl_info
      end

      def event_status(time, ssl_info)
        {
          'timestamp' => time.to_epochmillis,
          'name' => 'ssl_status',
          'value' => 1,
          'host' => host,
          'port' => port,
          'ssl_version' => ssl_info.ssl_version,
          'ssl_dn' => ssl_info.subject_s
        }
      end

      def event_status_failure(time)
        {
          'timestamp' => time.to_epochmillis,
          'name' => 'ssl_status',
          'value' => 0,
          'host' => host,
          'port' => port
        }
      end

      def event_expirency(time, ssl_info)
        {
          'timestamp' => time.to_epochmillis,
          'name' => 'ssl_expirency',
          'value' => ssl_info.expire_in_day(time),
          'host' => host,
          'port' => port,
          'ssl_version' => ssl_info.ssl_version,
          'ssl_dn' => ssl_info.subject_s
        }
      end

      def now
        Fluent::Engine.now
      end

      # ssl info
      #  to encapsulate extracted ssl information
      SslInfo = Struct.new(:cert, :cert_chain, :ssl_version) do
        def subject_s
          cert.subject.to_s
        end

        def expire_in_day(from = Date.today)
          from = from.to_time.to_date
          expire_in = cert.not_after.to_date

          (expire_in - from).to_i
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
          Timeout.timeout(timeout) do
            tcp_socket = TCPSocket.open(host, port)
            ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, ssl_context)
            ssl_socket.connect

            # cert_store.verify(ssl_socket.peer_cert, ssl_socket.peer_cert_chain)

            ssl_info = SslInfo.new(
              OpenSSL::X509::Certificate.new(ssl_socket.peer_cert),
              ssl_socket.peer_cert_chain,
              ssl_socket.ssl_socket.ssl_version
            )

            ssl_socket.sysclose
            tcp_socket.close

            ssl_info
          end
        end

        def store
          OpenSSL::X509::Store.new.tap do |store|
            store.set_default_paths if !ca_path && !ca_file

            cert_store.add_path(ca_path) if ca_path
            cert_store.add_file(ca_file) if ca_file
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
