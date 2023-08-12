# frozen_string_literal: true


class Time
  def to_epochmillis
    (to_f * 1000).to_i
  end

  def to_iso
    iso8601(3)
  end
end
