# frozen_string_literal: true

require 'helper'
require 'fluent/plugin/in_ssl_file_check'

# unit test for SslFileCheckInputTest / ssl_check input plugin
class SslFileCheckInputTest < Test::Unit::TestCase
  DEFAULT_CONF = %(
    paths cert.pem
  )
  TEST_TIME = Time.parse('2023-07-07T00:00:00.000Z')

  setup do
    Fluent::Test.setup

    Socket.stubs(:gethostname).returns('test-hostname')
    Timecop.freeze(TEST_TIME)
  end

  teardown do
    Timecop.return
  end

  # configuration
  sub_test_case 'configuration' do
    test 'default configuration' do
      driver = create_driver
      input = driver.instance

      assert input.paths
      refute input.paths.empty?

      assert_equal Fluent::Plugin::SslFileCheckInput::DEFAULT_TAG, input.tag
      assert_equal Fluent::Plugin::SslFileCheckInput::DEFAULT_INTERVAL, input.interval
      assert_equal Fluent::Plugin::SslFileCheckInput::DEFAULT_LOG_EVENTS, input.log_events
      assert_equal Fluent::Plugin::SslFileCheckInput::DEFAULT_METRIC_EVENTS, input.metric_events
      assert_equal Fluent::Plugin::SslFileCheckInput::DEFAULT_EVENT_PREFIX, input.event_prefix
      assert_equal Fluent::Plugin::SslFileCheckInput::DEFAULT_TIMESTAMP_FORMAT, input.timestamp_format

      assert_equal nil, input.ca_path
      assert_equal nil, input.ca_file
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

    test 'paths can be empty' do
      conf = %(
      )
      driver = create_driver(conf)
      input = driver.instance

      assert_equal [], input.paths
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
    test 'check generates log with error for non usable certificate file' do
      conf = %(
        paths /non-existing/certificate.pem
        interval 1
      )
      driver = create_driver(conf)
      driver.instance.check
      events = driver.events

      assert_equal 1, events.size
      assert_equal Fluent::Plugin::SslFileCheckInput::DEFAULT_TAG, events.first.first
      assert_equal({ 'timestamp' => '2023-07-07T00:00:00.000Z',
                     'status' => 0,
                     'host' => 'test-hostname',
                     'port' => nil,
                     'path' => '/non-existing/certificate.pem',
                     'ssl_version' => nil,
                     'ssl_dn' => nil,
                     'serial' => nil,
                     'ssl_not_after' => nil,
                     'expire_in_days' => nil,
                     'error_class' => 'Errno::ENOENT' },
                   events.first.last)
    end

    test 'check generates log with a mocked certificate file' do
      conf = %(
        paths /mocked/certificate.pem
        interval 1
      )
      driver = create_driver(conf)
      mock_driver_fetch_ssl_info(driver, '/mocked/certificate.pem')
      driver.instance.check
      events = driver.events

      assert_equal 1, events.size
      assert_equal Fluent::Plugin::SslFileCheckInput::DEFAULT_TAG, events.first.first
      assert_equal({ 'timestamp' => '2023-07-07T00:00:00.000Z',
                     'status' => 1,
                     'host' => 'localhost',
                     'port' => nil,
                     'path' => '/mocked/certificate.pem',
                     'ssl_version' => 'ssl_version_test',
                     'ssl_dn' => 'CN=TEST',
                     'serial' => '0',
                     'ssl_not_after' => '2025-07-06T00:00:00.000Z',
                     'expire_in_days' => 730 },
                   events.first.last)
    end

    test 'check generates metric with error for non usable certificate file' do
      conf = %(
        paths /non-existing/certificate.pem
        interval 1
        log_events false
        metric_events true
        timestamp_format epochmillis
      )
      driver = create_driver(conf)
      driver.instance.check
      events = driver.events

      assert_equal 1, events.size
      assert_equal Fluent::Plugin::SslFileCheckInput::DEFAULT_TAG, events.first.first
      assert_equal({ 'host' => 'test-hostname',
                     'port' => nil,
                     'path' => '/non-existing/certificate.pem',
                     'timestamp' => 1_688_688_000_000,
                     'metric_name' => 'ssl_status',
                     'metric_value' => 0,
                     'ssl_dn' => nil,
                     'serial' => nil,
                     'ssl_version' => nil,
                     'ssl_not_after' => nil }, events[0].last)
    end

    test 'check generates metric with a mocked certificate file' do
      conf = %(
        paths /mocked/certificate.pem
        interval 1
        log_events false
        metric_events true
        timestamp_format epochmillis
      )
      driver = create_driver(conf)
      mock_driver_fetch_ssl_info(driver, '/mocked/certificate.pem')
      driver.instance.check
      events = driver.events

      assert_equal 2, events.size
      assert_equal Fluent::Plugin::SslFileCheckInput::DEFAULT_TAG, events[0].first
      assert_equal({ 'host' => 'localhost',
                     'port' => nil,
                     'path' => '/mocked/certificate.pem',
                     'timestamp' => 1_688_688_000_000,
                     'metric_name' => 'ssl_status',
                     'metric_value' => 1,
                     'ssl_dn' => 'CN=TEST',
                     'serial' => '0',
                     'ssl_version' => 'ssl_version_test',
                     'ssl_not_after' => '2025-07-06T00:00:00.000Z' }, events[0].last)
      assert_equal Fluent::Plugin::SslFileCheckInput::DEFAULT_TAG, events[1].first
      assert_equal({ 'host' => 'localhost',
                     'port' => nil,
                     'path' => '/mocked/certificate.pem',
                     'timestamp' => 1_688_688_000_000,
                     'metric_name' => 'ssl_expirency',
                     'metric_value' => 730,
                     'ssl_dn' => 'CN=TEST',
                     'serial' => '0' }, events[1].last)
    end
  end

  private

  def create_driver(conf = DEFAULT_CONF)
    Fluent::Test::Driver::Input.new(Fluent::Plugin::SslFileCheckInput).configure(conf)
  end

  def mock_driver_fetch_ssl_info(driver, certificate_path)
    driver.instance.define_singleton_method(:fetch_ssl_info) do |_filepath|
      certificate = OpenSSL::X509::Certificate.new.tap do |cert|
        cert.subject = OpenSSL::X509::Name.parse 'CN=TEST'
        cert.not_after = TEST_TIME + (2 * 365 * 24 * 60 * 60)  # 2 years
      end

      Fluent::Plugin::SslCheck::SslInfo.new(
        host: 'localhost',
        path: certificate_path,
        cert: certificate,
        ssl_version: 'ssl_version_test',
        time: TEST_TIME
      )
    end
  end
end
