# frozen_string_literal: true

require 'helper'
require 'fluent/plugin/in_ssl_check'

# unit test for SslCheckInputTest / ssl_check input plugin
class SslCheckInputTest < Test::Unit::TestCase
  setup do
    Fluent::Test.setup
  end

  # configuration
  sub_test_case 'configuration' do
    test 'default configuration' do
      driver = create_driver
      input = driver.instance

      assert_equal Fluent::Plugin::SslCheckInput::DEFAULT_TAG, input.tag
      assert_equal Fluent::Plugin::SslCheckInput::DEFAULT_HOST, input.host
      assert_equal Fluent::Plugin::SslCheckInput::DEFAULT_PORT, input.port
      assert_equal Fluent::Plugin::SslCheckInput::DEFAULT_TIME, input.interval
      assert_equal nil, input.ca_path
      assert_equal nil, input.ca_file
      assert_equal Fluent::Plugin::SslCheckInput::DEFAULT_TIMEOUT, input.timeout
      assert_equal Fluent::Plugin::SslCheckInput::DEFAULT_LOG_EVENTS, input.log_events
      assert_equal Fluent::Plugin::SslCheckInput::DEFAULT_METRIC_EVENTS, input.metric_events
      assert_equal Fluent::Plugin::SslCheckInput::DEFAULT_EVENT_PREFIX, input.event_prefix
    end

    test 'tag can not be empty' do
      conf = %(
        #{DEFAULT_CONF}
        tag
      )
      assert_raise(Fluent::ConfigError) do
        create_driver(conf)
      end
    end

    test 'host can not be empty' do
      conf = %(
        #{DEFAULT_CONF}
        host
      )
      assert_raise(Fluent::ConfigError) do
        create_driver(conf)
      end
    end

    test 'port can not be < 1' do
      conf = %(
        #{DEFAULT_CONF}
        port 0
      )
      assert_raise(Fluent::ConfigError) do
        create_driver(conf)
      end
    end

    test 'interval can not be < 1' do
      conf = %(
        #{DEFAULT_CONF}
        interval 0
      )
      assert_raise(Fluent::ConfigError) do
        create_driver(conf)
      end
    end

    test 'ca_path should be a valid directory' do
      conf = %(
        #{DEFAULT_CONF}
        ca_path /nonexistent/dir
      )
      assert_raise(Fluent::ConfigError) do
        create_driver(conf)
      end
    end

    test 'ca_file should be a valid file' do
      conf = %(
        #{DEFAULT_CONF}
        ca_file /nonexistent/file
      )
      assert_raise(Fluent::ConfigError) do
        create_driver(conf)
      end
    end
  end

  # check
  sub_test_case 'check' do
    test 'check generates log with non existing service' do
      conf = %(
        #{DEFAULT_CONF}
        host 127.0.0.2
        port 1272
        interval 1
      )
      driver = create_driver(conf)

      Timecop.freeze(MOCKED_TIME) do
        driver.instance.check
      end
      events = driver.events

      assert_equal 1, events.size
      assert_equal Fluent::Plugin::SslCheckInput::DEFAULT_TAG, events.first.first
      assert_equal({ 'timestamp' => '2023-07-07T00:00:00.000+02:00',
                     'status' => 0,
                     'host' => '127.0.0.2',
                     'port' => 1272,
                     'ssl_version' => nil,
                     'ssl_dn' => nil,
                     'ssl_not_after' => nil,
                     'expire_in_days' => nil },
                   events.first.last)
    end

    test 'check generates log with mocked answer' do
      driver = create_driver
      mock_driver_ssl_info(driver)

      Timecop.freeze(MOCKED_TIME) do
        driver.instance.check
      end
      events = driver.events

      assert_equal 1, events.size
      assert_equal Fluent::Plugin::SslCheckInput::DEFAULT_TAG, events.first.first
      assert_equal({ 'timestamp' => '2023-07-07T00:00:00.000+02:00',
                     'status' => 1,
                     'host' => 'localhost',
                     'port' => 443,
                     'ssl_version' => 'ssl_version_test',
                     'ssl_dn' => '/CN=TEST',
                     'ssl_not_after' => '2025-07-05T22:00:00.000Z',
                     'expire_in_days' => 730 },
                   events.first.last)
    end

    test 'check generates metric with non existing service' do
      conf = %(
        #{DEFAULT_CONF}
        host 127.0.0.2
        port 1272
        interval 1
        log_events false
        metric_events true
        timestamp_format epochmillis
      )
      driver = create_driver(conf)

      Timecop.freeze(MOCKED_TIME) do
        driver.instance.check
      end
      events = driver.events

      assert_equal 1, events.size
      assert_equal Fluent::Plugin::SslCheckInput::DEFAULT_TAG, events[0].first
      assert_equal({ 'host' => '127.0.0.2',
                     'port' => 1272,
                     'timestamp' => 1_688_680_800_000,
                     'metric_name' => 'ssl_status',
                     'metric_value' => 0,
                     'ssl_dn' => nil,
                     'ssl_version' => nil,
                     'ssl_not_after' => nil }, events[0].last)
    end

    test 'check generates metric with mocked answer' do
      conf = %(
        #{DEFAULT_CONF}
        host 127.0.0.2
        port 1272
        interval 1
        log_events false
        metric_events true
        timestamp_format epochmillis
      )
      driver = create_driver(conf)
      mock_driver_ssl_info(driver)

      Timecop.freeze(MOCKED_TIME) do
        driver.instance.check
      end
      events = driver.events

      assert_equal 2, events.size
      assert_equal Fluent::Plugin::SslCheckInput::DEFAULT_TAG, events[0].first
      assert_equal({ 'host' => '127.0.0.2',
                     'port' => 1272,
                     'timestamp' => 1_688_680_800_000,
                     'metric_name' => 'ssl_status',
                     'metric_value' => 1,
                     'ssl_dn' => '/CN=TEST',
                     'ssl_version' => 'ssl_version_test',
                     'ssl_not_after' => '2025-07-05T22:00:00.000Z' }, events[0].last)
      assert_equal Fluent::Plugin::SslCheckInput::DEFAULT_TAG, events[1].first
      assert_equal({ 'host' => '127.0.0.2',
                     'port' => 1272,
                     'timestamp' => 1_688_680_800_000,
                     'metric_name' => 'ssl_expirency',
                     'metric_value' => 730,
                     'ssl_dn' => '/CN=TEST' }, events[1].last)
    end
  end

  private

  DEFAULT_CONF = %()
  MOCKED_TIME = Time.parse('2023-07-07')
  def create_driver(conf = DEFAULT_CONF)
    Fluent::Test::Driver::Input.new(Fluent::Plugin::SslCheckInput).configure(conf)
  end

  def mock_driver_ssl_info(driver)
    driver.instance.define_singleton_method :fetch_ssl_info do
      certificate = OpenSSL::X509::Certificate.new.tap do |cert|
        cert.subject = OpenSSL::X509::Name.parse '/CN=TEST'
        cert.not_after = MOCKED_TIME + (2 * 365 * 24 * 60 * 60)  # 2 years
      end

      Fluent::Plugin::SslCheckInput::SslInfo.new(
        cert: certificate,
        ssl_version: 'ssl_version_test',
        time: MOCKED_TIME
      )
    end
  end
end
