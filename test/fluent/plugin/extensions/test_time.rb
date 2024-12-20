# frozen_string_literal: true

require 'helper'
require 'fluent/plugin/extensions/time'

class TimeTest < Test::Unit::TestCase
  setup do
    Fluent::Test.setup
  end

  sub_test_case '.to_epochmillis' do
    test 'it formats to epochmillis format' do
      assert_equal 1_672_534_861_000, Time.parse('2023-01-01T01:01:01Z').to_epochmillis
    end
  end

  sub_test_case '.to_iso' do
    test 'it formats to iso8601 format' do
      assert_equal '2023-01-01T01:01:01.000Z', Time.parse('2023-01-01T01:01:01Z').to_iso
    end
  end
end
