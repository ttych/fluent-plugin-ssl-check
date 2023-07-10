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

      def start
        super

        timer_execute(:ssl_check_timer, interval, repeat: true, &method(:check))
      end

      def check
        ssl_info = @ssl_client.check

        #         tag = "myapp.access"
        # time = Fluent::Engine.now
        # record = {"message"=>"body"}
        # router.emit(tag, time, record)

        # es = MultiEventStream.new
        # records.each do |record|
        #   es.add(time, record)
        # end
        # router.emit_stream(tag, es)
      rescue StandardError
      end

      # ssl client
      #  to check ssl status
      class SslClient
        SslInfo = Struct.new(:cert, :cert_chain, :ssl_version)

        attr_reader :host, :port, :ca_path, :ca_file, :timeout

        def initialize(host:, port:, ca_path: nil, ca_file: nil, timeout: 5)
          @host = host
          @port = port
          @ca_path = ca_path
          @ca_file = ca_file
          @timeout = timeout
        end

        def check
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
          @store ||= OpenSSL::X509::Store.new.tap do |store|
            store.set_default_paths if !ca_path && !ca_file

            cert_store.add_path(ca_path) if ca_path
            cert_store.add_file(ca_file) if ca_file
          end
        end

        def ssl_context
          @ssl_context ||= OpenSSL::SSL::SSLContext.new.tap do |ssl_context|
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
