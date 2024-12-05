# frozen_string_literal: true

#
# Copyright 2024- Thomas Tych
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

require 'openssl'

require_relative 'extensions/time'
require_relative 'ssl_check'

module Fluent
  module Plugin
    class SslFileCheckInput < Fluent::Plugin::Input
      NAME = 'ssl_file_check'
      Fluent::Plugin.register_input(NAME, self)

      include Fluent::Plugin::SslCheck::SslInputEmit

      DEFAULT_TAG = NAME
      DEFAULT_INTERVAL = 600
      DEFAULT_LOG_EVENTS = true
      DEFAULT_METRIC_EVENTS = false
      DEFAULT_EVENT_PREFIX = ''
      DEFAULT_TIMESTAMP_FORMAT = :iso

      desc 'Tag to emit events on'
      config_param :tag, :string, default: DEFAULT_TAG

      desc 'Paths of local certificate to check'
      config_param :paths, :array, default: [], value_type: :string

      desc 'Interval for the check execution'
      config_param :interval, :time, default: DEFAULT_INTERVAL

      desc 'CA path to load'
      config_param :ca_path, :string, default: nil
      desc 'CA file to load'
      config_param :ca_file, :string, default: nil

      desc 'Emit log events'
      config_param :log_events, :bool, default: DEFAULT_LOG_EVENTS
      desc 'Emit metric events'
      config_param :metric_events, :bool, default: DEFAULT_METRIC_EVENTS
      desc 'Event prefix'
      config_param :event_prefix, :string, default: DEFAULT_EVENT_PREFIX
      desc 'Timestamp format'
      config_param :timestamp_format, :enum, list: %i[iso epochmillis], default: DEFAULT_TIMESTAMP_FORMAT

      helpers :timer

      # rubocop:disable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity
      def configure(conf)
        super

        raise Fluent::ConfigError, 'tag can not be empty.' if !tag || tag.empty?
        raise Fluent::ConfigError, 'paths can not be empty.' unless paths
        raise Fluent::ConfigError, 'interval can not be < 1.' if !interval || interval < 1
        raise Fluent::ConfigError, 'ca_path should be a dir.' if ca_path && !File.directory?(ca_path)
        raise Fluent::ConfigError, 'ca_file should be a file.' if ca_file && !File.file?(ca_file)

        log.warn("#{NAME}: paths is empty, nothing to process") if paths.empty?
      end
      # rubocop:enable Metrics/CyclomaticComplexity, Metrics/PerceivedComplexity

      def start
        super

        timer_execute(:ssl_file_check_timer, 1, repeat: false, &method(:check)) if interval > 60

        timer_execute(:ssl_file_check_timer, interval, repeat: true, &method(:check))
      end

      # rubocop:disable Lint/SuppressedException
      def check
        paths.each do |cert_path|
          ssl_info = fetch_ssl_info(cert_path)
          emit_logs(ssl_info) if log_events
          emit_metrics(ssl_info) if metric_events
        rescue StandardError
        end
      end
      # rubocop:enable Lint/SuppressedException

      def fetch_ssl_info(filepath)
        ssl_file = Fluent::Plugin::SslCheck::FileChecker.new(filepath, ca_path: ca_path, ca_file: ca_file)
        ssl_file.ssl_info
      end
    end
  end
end
