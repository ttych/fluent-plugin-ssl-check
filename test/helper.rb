# frozen_string_literal: true

require 'test-unit'
require 'fluent/test'
require 'fluent/test/driver/input'
require 'fluent/test/helpers'

require 'timecop'

Test::Unit::TestCase.include(Fluent::Test::Helpers)
Test::Unit::TestCase.extend(Fluent::Test::Helpers)

def test_data_path(filename)
  test_dir = File.expand_path(__dir__)
  filename_path = File.join(test_dir, 'data', filename)
  raise "#{filename_path} does not exists" unless File.file?(filename_path)

  filename_path
end
