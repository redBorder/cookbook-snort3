# Cookbook:: snort
# Resource:: config

actions :add, :remove
default_action :add

attribute :sensor_id, kind_of: Integer, default: 0
attribute :groups, kind_of: Array, default: []

attribute :s3_access_key_id, kind_of: String, default: ''
attribute :s3_secret_key_id, kind_of: String, default: ''
attribute :s3_region, kind_of: String, default: 'us-east-1'
attribute :s3_bucket, kind_of: String, default: 'bucket'
attribute :s3_endpoint, kind_of: String, default: ''
attribute :s3_verify_ssl, kind_of: [TrueClass, FalseClass], default: false
attribute :enable_s3, kind_of: [TrueClass, FalseClass], default: true
attribute :s3_https_scheme, kind_of: [TrueClass, FalseClass], default: false
attribute :s3_use_real_name, kind_of: [TrueClass, FalseClass], default: true
attribute :rules_file, kind_of: String, default: 'file_magic.rules'
attribute :capture_memcap, kind_of: Integer, default: 2048
attribute :capture_max_size, kind_of: Integer, default: 52428800
attribute :capture_min_size, kind_of: Integer, default: 1
attribute :capture_block_size, kind_of: Integer, default: 32768
attribute :max_files_cached, kind_of: Integer, default: 65536
attribute :show_data_depth, kind_of: Integer, default: 1024
