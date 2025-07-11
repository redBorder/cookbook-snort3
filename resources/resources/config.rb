# Cookbook:: snort
# Resource:: config

actions :add, :remove
default_action :add

attribute :sensor_id, kind_of: Integer, default: 0
attribute :groups, kind_of: Array, default: []
attribute :http_param_threshold, kind_of: Float, default: 0.95
