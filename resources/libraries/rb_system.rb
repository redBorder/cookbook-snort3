module System
  module Helpers
    def check_bpctl_mod
      module_loaded = `lsmod | grep bpctl_mod`
      if module_loaded.strip.empty?
        Chef::Log.warn('bpctl_mod is not loaded. injecting the module...')
        system('bpctl_start')
      else
        Chef::Log.info('bpctl_mod is already loaded.')
      end
    end
  end
end
