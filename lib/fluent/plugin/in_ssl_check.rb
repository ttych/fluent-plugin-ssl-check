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

      helpers :timer

      def configure(conf)
        super

        raise Fluent::ConfigError, 'tag can not be empty.' if !tag || tag.empty?
        raise Fluent::ConfigError, 'host can not be empty.' if !host || host.empty?
        raise Fluent::ConfigError, 'port can not be < 1' if !port || port < 1
        raise Fluent::ConfigError, 'interval can not be < 1.' if !interval || interval < 1
        raise Fluent::ConfigError, 'ca_path should be a dir.' if ca_path && !File.directory?(ca_path)
        raise Fluent::ConfigError, 'ca_file should be a file.' if ca_file && !File.file?(ca_file)
      end

      def start
        super

        timer_execute(:ssl_check_timer, interval, repeat: true, &method(:check))
      end

      def check
        # require "socket"
        # require "openssl"

        # cert_store = OpenSSL::X509::Store.new
        # cert_store.set_default_paths
        # # cert_store.add_file 'cacert.pem'
        # cert_store.add_path '/etc/ssl/certs'
        # # cert_store.add_file '/etc/ssl/certs/ca-certificates.crt'
        # # cert_store.add_file '/etc/ssl/certs/GlobalSign_Root_CA.pem'

        # ssl_context = OpenSSL::SSL::SSLContext.new
        # ssl_context.verify_mode = OpenSSL::SSL::VERIFY_PEER
        # # ssl_context.verify_depth = 2
        # ssl_context.cert_store = cert_store
        # # ssl_context.min_version = nil
        # ssl_context.min_version = OpenSSL::SSL::TLS1_1_VERSION
        # # ssl_context.max_version = nil
        # ssl_context.max_version = OpenSSL::SSL::TLS1_2_VERSION

        # puts ssl_context.options.inspect

        # tcp_socket = TCPSocket.open 'www.youtube.com', 443
        # ssl_socket = OpenSSL::SSL::SSLSocket.new tcp_socket, ssl_context

        # ssl_socket.connect

        # cert = OpenSSL::X509::Certificate.new(ssl_socket.peer_cert)

        # puts cert.inspect

        # binding.irb

        # puts cert_store.verify(cert, ssl_socket.peer_cert_chain)

        # puts ssl_socket.ssl_version
      end

      def shutdown
        super
      end
    end
  end
end
