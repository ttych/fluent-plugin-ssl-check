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

  private

  DEFAULT_CONF = %()

  def create_driver(conf = DEFAULT_CONF)
    Fluent::Test::Driver::Input.new(Fluent::Plugin::SslCheckInput).configure(conf)
  end
end
