# frozen_string_literal: true

module Fluent
  # extension
  class EventTime
    def to_epochmillis
      @sec * 1_000 + @nsec / 1_000_000
    end
  end
end
