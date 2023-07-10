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
    # test 'check non existing service' do
    #   conf = %(
    #     #{DEFAULT_CONF}
    #     host 127.0.0.2
    #     port 1272
    #     interval 1
    #   )
    #   driver = create_driver(conf)
    #   mock_driver_timer(driver)
    #   # driver.run(expect_emits: 1, timeout: 5)
    #   driver.instance.check

    #   events = driver.events

    #   assert_equal 1, events.size
    #   assert_equal Fluent::Plugin::SslCheckInput::DEFAULT_TAG, events.first.first
    #   assert_equal({"host" => "127.0.0.2",
    #                  "name" => "ssl_status",
    #                  "port" => 1272,
    #                  "timestamp" => 1688680800000,
    #                  "value" => 0}, events.first.last)
    # end

    test 'check with fake ssl_info' do
      driver = create_driver
      mock_driver_timer(driver)
      mock_driver_ssl_info(driver)

      # driver.run(expect_emits: 2, timeout: 5)
      driver.instance.check

      events = driver.events

      assert_equal 2, events.size
      assert_equal Fluent::Plugin::SslCheckInput::DEFAULT_TAG, events[0].first
      assert_equal({ 'host' => 'localhost',
                     'name' => 'ssl_status',
                     'port' => 443,
                     'timestamp' => 1_688_680_800_000,
                     'value' => 1,
                     'ssl_dn' => '/CN=TEST',
                     'ssl_version' => 'ssl_version' }, events[0].last)
      assert_equal Fluent::Plugin::SslCheckInput::DEFAULT_TAG, events[1].first
      assert_equal({ 'host' => 'localhost',
                     'name' => 'ssl_expirency',
                     'port' => 443,
                     'timestamp' => 1_688_680_800_000,
                     'value' => 729,
                     'ssl_dn' => '/CN=TEST',
                     'ssl_version' => 'ssl_version' }, events[1].last)
    end
  end

  private

  DEFAULT_CONF = %()
  MOCKED_TIME = Time.parse('2023-07-07')
  def create_driver(conf = DEFAULT_CONF)
    Fluent::Test::Driver::Input.new(Fluent::Plugin::SslCheckInput).configure(conf)
  end

  def mock_driver_timer(driver)
    driver.instance.define_singleton_method :now do
      Fluent::EventTime.from_time(MOCKED_TIME)
    end
  end

  def mock_driver_ssl_info(driver)
    driver.instance.define_singleton_method :fetch_ssl_info do
      certificate = OpenSSL::X509::Certificate.new.tap do |cert|
        cert.subject = OpenSSL::X509::Name.parse '/CN=TEST'
        cert.not_after = MOCKED_TIME + 2 * 365 * 24 * 60 * 60  # 2 years
      end

      Fluent::Plugin::SslCheckInput::SslInfo.new(
        certificate,
        nil,
        'ssl_version'
      )
    end
  end
end
