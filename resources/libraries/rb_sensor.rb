module Sensor
  module Helpers
    def get_sensor_id(node)
      begin
        sensor_id = node['redborder']['sensor_id'].to_i
      rescue
        sensor_id = 0
      end
    end
  end
end
