module Snort3
  module Helpers
    def get_snort_args(inline, iface, mode, sbypass_upper, sbypass_lower, sbypass_rate, malware_file_capture)
      args = if inline
               args = "--daq redborder_afpacket --daq-mode inline --daq-var fanout_type=hash -i #{iface}"
               args += ' -k none -s 65535' if malware_file_capture
               args += " --daq-var sbypassupperthreshold=#{sbypass_upper}"
               args += " --daq-var sbypasslowerthreshold=#{sbypass_lower}"
               args += " --daq-var sbypasssamplingrate=#{sbypass_rate}"
               args += ' --treat-drop-as-alert' if mode == 'IDS_FWD' || mode == 'IDS'
               args
             else
               args = "--daq redborder_afpacket --daq-var fanout_type=hash -i #{iface}"
               args += ' -k none -s 65535' if malware_file_capture
               args += ' --daq-var sbypassupperthreshold=0'
               args += ' --daq-var sbypasslowerthreshold=0'
               args += ' --daq-var sbypasssamplingrate=0'
               args += ' --treat-drop-as-alert' if mode == 'IDS_SPAN' || mode
               args
             end

      args = "-Q #{args}" if mode == 'IPS'
      args
    end

    def get_output_plugin(node)
      if node['redborder']['cloud'] == true || node['redborder']['cloud'].to_s == '1'
        'alert_http'
      else
        'alert_syslog'
      end
    end

    def get_software_bypass(group)
      case group['pfring_sbypass_profile']
      when '1' # connectivity
        sbypass_upper = 60
        sbypass_lower = 10
        sbypass_rate  = 5000
      when '2' # balanced
        sbypass_upper = 75
        sbypass_lower = 25
        sbypass_rate  = 2000
      when '3' # security
        sbypass_upper = 90
        sbypass_lower = 40
        sbypass_rate  = 2000
      else
        sbypass_upper = 0
        sbypass_lower = 0
        sbypass_rate  = 0
      end
      [sbypass_upper, sbypass_lower, sbypass_rate]
    end

    def get_instance_parameters(group)
      segment = group['segments'].join(' ')
      iface = `ip link show master #{group['segments'].join(' ')} | grep '^[0-9]' | awk '{print $2}' | cut -d':' -f1 | paste -sd ":"`.chomp!
      threads = group['cpu_list'].size
      cpu_cores = group['cpu_list'].join(' ')
      mode = group['mode']
      inline = (mode != 'IDS' && mode != 'IDS_SPAN') && (mode == 'IPS' || mode == 'IDS_FWD' || mode == 'IPS_TEST')

      sbypass_upper, sbypass_lower, sbypass_rate = get_software_bypass(group)

      {
        segment: segment,
        iface: iface,
        threads: threads,
        cpu_cores: cpu_cores,
        mode: mode,
        inline: inline,
        sbypass_upper: sbypass_upper,
        sbypass_lower: sbypass_lower,
        sbypass_rate: sbypass_rate,
      }
    end

    def get_ml_detection_action(mode)
      if mode == 'IDS' || mode == 'IDS_SPAN' || mode == 'IDS_FWD'
        'alert'
      else
        'drop'
      end
    end

    def get_snort_default_ml_actions(node)
      ml_detection_enabled            = node.dig('redborder', 'ml_detection', 'enabled')            || false
      ml_detection_threshold          = node.dig('redborder', 'ml_detection', 'threshold')          || 0.95
      ml_detection_action             = node.dig('redborder', 'ml_detection', 'action')             || 'alert'
      ml_detection_uri_depth          = node.dig('redborder', 'ml_detection', 'uri_depth')          || -1
      ml_detection_client_body_depth  = node.dig('redborder', 'ml_detection', 'client_body_depth')  || 100

      {
        ml_detection_enabled: ml_detection_enabled,
        ml_detection_threshold: ml_detection_threshold,
        ml_detection_action: ml_detection_action,
        ml_detection_uri_depth: ml_detection_uri_depth,
        ml_detection_client_body_depth: ml_detection_client_body_depth,
      }
    end
  end
end
