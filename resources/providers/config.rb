# Cookbook:: snort3
# Provider:: config

action :add do
  begin
    sensor_id = new_resource.sensor_id
    groups = new_resource.groups

    ml_actions = Snort3::Helpers.get_snort_default_ml_actions(node)

    System::Helpers.check_bpctl_mod

    dnf_package 'snort3' do
      action :upgrade
    end

    valid_instance_names = []

    execute 'rb_copy_raw_alerts' do
      command '/bin/env WAIT=1 /usr/lib/redborder/rb_copy_raw_alerts.sh'
      action :run
    end

    groups.each do |group|
      group_name = group['name']
      default_added = false
      group['bindings']
        .keys
        .map(&:to_i)
        .sort
        .map(&:to_s)
        .each do |_id_str|
        default_added = SnortGroup::Helpers.configure_group(group, node, default_added)

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

        template "/etc/snort/#{instance_name}/config.lua" do
          source 'config.lua.erb'
          cookbook 'snort3'
          owner 'root'
          group 'root'
          mode '0644'
          retries 2
          variables(instance_name: instance_name, group: group, sensor_id: Sensor::Helpers.get_sensor_id(node), group_name: group_name, ml_detection_threshold: ml_actions[:ml_detection_threshold], ml_detection_enabled: ml_actions[:ml_detection_enabled], ml_detection_uri_depth: ml_actions[:ml_detection_uri_depth], ml_detection_client_body_depth: ml_actions[:ml_detection_client_body_depth])
          notifies :stop, "service[snort3@#{instance_name}.service]", :delayed
          notifies :start, "service[snort3@#{instance_name}.service]", :delayed
        end

        instance_params = Snort3::Helpers.get_instance_parameters(group)
        malware_file_capture = instance_params[:malware]

        args = Snort3::Helpers.get_snort_args(
          instance_params[:inline],
          instance_params[:iface],
          instance_params[:mode],
          instance_params[:sbypass_upper],
          instance_params[:sbypass_lower],
          instance_params[:sbypass_rate],
          malware_file_capture
        )

        execute 'rb_configure_ifaces' do
          command '/bin/env WAIT=1 /usr/lib/redborder/rb_configure_ifaces.sh'
          run_action :run
        end

        template "/etc/snort/#{instance_name}/env" do
          source 'env.erb'
          cookbook 'snort3'
          owner 'root'
          group 'root'
          mode '0644'
          retries 2
          variables(segment: instance_params[:segment], autobypass: autobypass, iface: instance_params[:iface], cpu_cores: instance_params[:cpu_cores], threads: instance_params[:threads], mode: instance_params[:mode], inline: instance_params[:inline], args: args, output_plugin: Snort3::Helpers.get_output_plugin(node))
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

        template "/etc/snort/#{instance_name}/ml.rules" do
          source 'ml.rules.erb'
          cookbook 'snort3'
          owner 'root'
          group 'root'
          mode '0644'
          retries 2
          variables(ml_detection_action: Snort3::Helpers.get_ml_detection_action(instance_params[:mode]))
        end

        template "/etc/snort/#{instance_name}/events.lua" do
          source 'empty.erb'
          cookbook 'snort3'
          owner 'root'
          group 'root'
          mode '0644'
          retries 2
          not_if { ::File.exist?("/etc/snort/#{instance_name}/events.lua") && !::File.zero?("/etc/snort/#{instance_name}/events.lua") }
        end

        template_paths = {
          'iplists/allowlist'    => "/etc/snort/#{instance_name}/iplists",
          'iplists/blacklist'    => "/etc/snort/#{instance_name}/iplists",
          'iplists/monitorlist'  => "/etc/snort/#{instance_name}/iplists",
          'geoips/rbgeoip'       => "/etc/snort/#{instance_name}/geoips",
        }

        template_paths.each do |relative_path, dir_path|
          directory dir_path do
            recursive true
            owner 'root'
            group 'root'
            mode '0755'
            action :create
          end

          template "/etc/snort/#{instance_name}/#{relative_path}" do
            source 'empty.erb'
            cookbook 'snort3'
            owner 'root'
            group 'root'
            mode '0644'
            retries 2
            action :create_if_missing
          end
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

        template "/etc/snort/#{instance_name}/snort_defaults.lua" do
          source 'snort_defaults.lua.erb'
          cookbook 'snort3'
          owner 'root'
          group 'root'
          mode '0644'
          retries 2
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
