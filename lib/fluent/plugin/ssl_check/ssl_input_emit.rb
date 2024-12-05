# frozen_string_literal: true

module Fluent
  module Plugin
    module SslCheck
      module SslInputEmit
        def emit_logs(ssl_info)
          record = {
            'timestamp' => ssl_info.time_utc.send("to_#{timestamp_format}"),
            'status' => ssl_info.status,
            'host' => ssl_info.host,
            'port' => ssl_info.port,
            'path' => ssl_info.path,
            'ssl_version' => ssl_info.ssl_version,
            'ssl_dn' => ssl_info.subject_s,
            'ssl_not_after' => ssl_info.not_after,
            'expire_in_days' => ssl_info.expire_in_days,
            'serial' => ssl_info.serial
          }
          record.update('error_class' => ssl_info.error_class) if ssl_info.error_class
          router.emit(tag, Fluent::EventTime.from_time(ssl_info.time_utc), record)
        end

        def emit_metrics(ssl_info)
          emit_metric_status(ssl_info)
          emit_metric_expirency(ssl_info)
        end

        def emit_metric_status(ssl_info)
          record = {
            'timestamp' => ssl_info.time_utc.send("to_#{timestamp_format}"),
            'metric_name' => 'ssl_status',
            'metric_value' => ssl_info.status,
            "#{event_prefix}host" => ssl_info.host,
            "#{event_prefix}port" => ssl_info.port,
            "#{event_prefix}path" => ssl_info.path,
            "#{event_prefix}ssl_dn" => ssl_info.subject_s,
            "#{event_prefix}ssl_version" => ssl_info.ssl_version,
            "#{event_prefix}ssl_not_after" => ssl_info.not_after,
            "#{event_prefix}serial" => ssl_info.serial
          }
          router.emit(tag, Fluent::EventTime.from_time(ssl_info.time_utc), record)
        end

        def emit_metric_expirency(ssl_info)
          return unless ssl_info.cert

          record = {
            'timestamp' => ssl_info.time_utc.send("to_#{timestamp_format}"),
            'metric_name' => 'ssl_expirency',
            'metric_value' => ssl_info.expire_in_days,
            "#{event_prefix}host" => ssl_info.host,
            "#{event_prefix}port" => ssl_info.port,
            "#{event_prefix}path" => ssl_info.path,
            "#{event_prefix}ssl_dn" => ssl_info.subject_s,
            "#{event_prefix}serial" => ssl_info.serial
          }
          router.emit(tag, Fluent::EventTime.from_time(ssl_info.time_utc), record)
        end
      end
    end
  end
end
