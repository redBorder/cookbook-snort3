# Cookbook:: snort3
# Provider:: config

action :add do
  begin
    sensor_id = new_resource.sensor_id
    groups = new_resource.groups

    dnf_package 'snort' do
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
          action :nothing
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

        iface = `ip link show master #{group['segments'].join(' ')} | grep '^[0-9]' | awk '{print $2}' | cut -d':' -f1 | paste -sd ":"`
        threads = group["cpu_list"].size * 2
        cpu_cores = group["cpu_list"].join(' ')
        mode = group["mode"]
        inline = if group["mode"] != "IDS" and group["mode"] != "IDS_SPAN" and group["mode"] != "IDS_FWD"
                   true
                  else
                    false
                  end

        args = if inline
                 "-Q --daq afpacket --daq-var fanout_type=hash -i #{iface}"
               else
                 "--daq afpacket --daq-var fanout_type=hash -i #{iface}"
               end 

        template "/etc/snort/#{instance_name}/env" do
          source 'env.erb'
          cookbook 'snort3'
          owner 'root'
          group 'root'
          mode '0644'
          retries 2
          variables(iface: iface, cpu_cores: cpu_cores, threads: threads, mode: mode, inline: inline, args: args)
          notifies :stop, "service[snort3@#{instance_name}.service]", :delayed
          notifies :start, "service[snort3@#{instance_name}.service]", :delayed
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
    ruby_block 'cleanup_old_snort3_systemd_services' do
      block do
        existing_service_files = []
        dir_path = "/sys/fs/cgroup/system.slice/system-snort3.slice/"

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

