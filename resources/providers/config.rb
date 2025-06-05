# Cookbook:: snort3
# Provider:: config

action :add do
  begin
    sensor_id = new_resource.sensor_id
    groups = new_resource.groups

    # temporary until we configure selinux
    ruby_block 'set_enforce_0' do
      block do
        selinux_status = `getenforce`

        if selinux_status.strip != 'Permissive'
          Chef::Log.warn('Setting SELinux to permissive mode...')
          system('setenforce 0')
        else
          Chef::Log.info('SELinux is already in permissive mode.')
        end
      end
      action :run
    end

    ruby_block 'check_bpctl_mod' do
      block do
        module_loaded = `lsmod | grep bpctl_mod`

        if module_loaded.strip.empty?
          Chef::Log.warn('bpctl_mod is not loaded. injecting the module...')
          system('bpctl_start')
        else
          Chef::Log.info('bpctl_mod is already loaded.')
        end
      end
      action :run
    end

    dnf_package 'snort3' do
      action :upgrade
      flush_cache [:before]
    end

    valid_instance_names = []

    groups.each do |group|
      name = group['name']

      bindings = group['bindings'].keys.map(&:to_i).sort

      bindings.each do |binding_id|
        vgroup = {}
        vgroup['ipvars']        = node['redborder']['snort']['default']['ipvars']
        vgroup['portvars']      = node['redborder']['snort']['default']['portvars']

        instance_name = "#{group['instances_group']}_#{group['name']}_#{binding_id}"

        valid_instance_names << "snort3@#{instance_name}.service"

        service "snort3@#{instance_name}.service" do
          action [:enable]
        end

        %w(reload restart stop start).each do |s_action|
          execute "#{s_action}_snort3@#{instance_name}" do
            command "/bin/env WAIT=1 /bin/systemctl #{s_action} snort3@#{instance_name}.service"
            ignore_failure true
            action :nothing
          end
        end

        directory "/etc/snort/#{instance_name}" do
          owner 'root'
          group 'root'
          mode '0755'
          recursive true
          action :create
        end

        directory "/var/log/snort/#{instance_name}" do
          owner 'root'
          group 'root'
          mode '0755'
          recursive true
          action :create
        end

        begin
          sensor_id = node['redborder']['sensor_id'].to_i
        rescue
          sensor_id = 0
        end

        template "/etc/snort/#{instance_name}/config.lua" do
          source 'config.lua.erb'
          cookbook 'snort3'
          owner 'root'
          group 'root'
          mode '0644'
          retries 2
          variables(instance_name: instance_name, group: group, sensor_id: sensor_id, name: name)
          notifies :stop, "service[snort3@#{instance_name}.service]", :delayed
          notifies :start, "service[snort3@#{instance_name}.service]", :delayed
        end

        iface = `ip link show master #{group['segments'].join(' ')} | grep '^[0-9]' | awk '{print $2}' | cut -d':' -f1 | paste -sd ":"`.chomp!
        threads = group['cpu_list'].size * 2
        cpu_cores = group['cpu_list'].join(' ')
        mode = group['mode']
        inline = (mode != 'IDS' && mode != 'IDS_SPAN') && (mode == 'IPS' || mode == 'IDS_FWD' || mode == 'IPS_TEST')
        args = if inline
                 args = "--daq afpacket --daq-mode inline --daq-var fanout_type=hash -i #{iface}" # IPS_TEST
                 args = "#{args} --treat-drop-as-alert" if mode == 'IDS_FWD' || mode == 'IDS'
                 args
               else
                 args = "--daq afpacket --daq-var fanout_type=hash -i #{iface}"
                 args = "#{args} --treat-drop-as-alert" if mode == 'IDS_SPAN' || mode
                 args
               end

        args = "-Q #{args}" if mode == 'IPS'

        output_plugin = ''
        output_plugin = if node['redborder']['cloud'] == true || node['redborder']['cloud'].to_s == '1'
                          'alert_http'
                        else
                          'alert_kafka'
                        end

        template "/etc/snort/#{instance_name}/env" do
          source 'env.erb'
          cookbook 'snort3'
          owner 'root'
          group 'root'
          mode '0644'
          retries 2
          variables(iface: iface, cpu_cores: cpu_cores, threads: threads, mode: mode, inline: inline, args: args, output_plugin: output_plugin)
          notifies :stop, "service[snort3@#{instance_name}.service]", :delayed
          notifies :start, "service[snort3@#{instance_name}.service]", :delayed
        end

        template "/etc/snort/#{instance_name}/snort.rules" do
          source 'empty.erb'
          cookbook 'snort3'
          owner 'root'
          group 'root'
          mode '0644'
          retries 2
          not_if { ::File.exist?("/etc/snort/#{instance_name}/snort.rules") && !::File.zero?("/etc/snort/#{instance_name}/snort.rules") }
        end

        template "/etc/snort/#{instance_name}/snort-variables.conf" do
          source 'snort-variables.conf.erb'
          cookbook 'snort3'
          owner 'root'
          group 'root'
          mode '0644'
          retries 2
          variables(vgroup: vgroup)
          notifies :stop, "service[snort3@#{instance_name}.service]", :delayed
          notifies :start, "service[snort3@#{instance_name}.service]", :delayed
        end
      end
    end

    ruby_block 'check_running_snort3_services' do
      block do
        running_services = `systemctl list-units --type=service --state=running | grep snort3 | awk '{print $1}'`.split("\n")
        invalid_services = running_services - valid_instance_names

        Chef::Log.info("Running snort3 services: #{running_services}")
        Chef::Log.info("Invalid snort3 services: #{invalid_services}")

        invalid_services.each do |invalid_service|
          next if invalid_service.empty?

          service_name = invalid_service.gsub('.service', '')
          system("systemctl stop #{service_name}")
          system("systemctl disable #{service_name}")

          Chef::Log.info("Stopped and disabled invalid service: #{service_name}")
        end
      end
      action :run
    end

    ruby_block 'cleanup_old_snort3_systemd_services' do
      block do
        existing_service_files = []
        dir_path = '/sys/fs/cgroup/system.slice/system-snort3.slice/'

        unless Dir.exist?(dir_path)
          Chef::Log.info("Directory #{dir_path} does not exist. Skipping cleanup of old Snort 3 services.")
          next
        end

        entries = Dir.entries(dir_path)
        pattern = /^snort3@\w+\.service$/

        entries.each do |entry|
          if entry.match?(pattern)
            existing_service_files.append(entry)
          end
        end

        old_service_files = existing_service_files - valid_instance_names

        Chef::Log.info("Old snort3 services to be disabled: #{old_service_files}")

        old_service_files.each do |old_instance_name|
          next if old_instance_name.empty?

          service_name = old_instance_name.gsub('.service', '')
          system("systemctl stop #{service_name}")
          system("systemctl disable #{service_name}")

          Chef::Log.info("Stopped and disabled service: #{service_name}")
        end
      end
      action :run
    end
  end
end

action :remove do
  begin
    Chef::Log.info('snort3 cookbook has been removed')
  rescue => e
    Chef::Log.error(e.message)
  end
end
