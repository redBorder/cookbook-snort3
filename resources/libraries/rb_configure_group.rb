module SnortGroup
  module Helpers
    def configure_group(group, node, default_added)
      vgroup = group['bindings'][id_str].to_hash.clone
      vgroup_name    = vgroup['name'].nil? ? 'default' : vgroup['name'].to_s
      vgroup['name'] = vgroup_name
      binding_id     = id_str.to_i
      vgroup['id']   = binding_id

      has_vlans   = vgroup['vlan_objects'] && !vgroup['vlan_objects'].empty?
      has_network = vgroup['network_objects'] && !vgroup['network_objects'].empty?

      if !has_vlans && !has_network
        if default_added
          return default_added
        else
          default_added = true
        end
      end

      if vgroup['ipvars'].nil? || vgroup['ipvars'].empty?
        vgroup['ipvars'] = node['redborder']['snort']['default']['ipvars']
      end

      if vgroup['portvars'].nil? || vgroup['portvars'].empty?
        vgroup['portvars'] = node['redborder']['snort']['default']['portvars']
      end

      default_added
    end
  end
end
