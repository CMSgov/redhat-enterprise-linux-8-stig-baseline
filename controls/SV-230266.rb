control 'SV-230266' do
  title 'RHEL 8 must prevent the loading of a new kernel for later execution.'
  desc 'Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.

Disabling kexec_load prevents an unsigned kernel image (that could be a windows kernel or modified vulnerable kernel) from being loaded. Kexec can be used subvert the entire secureboot process and should be avoided at all costs especially since it can load unsigned kernel images.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf'
  desc 'check', 'Verify the operating system is configured to disable kernel image loading with the following commands:

Check the status of the kernel.kexec_load_disabled kernel parameter.

$ sudo sysctl kernel.kexec_load_disabled

kernel.kexec_load_disabled = 1

If "kernel.kexec_load_disabled" is not set to "1" or is missing, this is a finding.

Check that the configuration files are present to enable this kernel parameter.

$ sudo grep -r kernel.kexec_load_disabled /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf:kernel.kexec_load_disabled = 1

If "kernel.kexec_load_disabled" is not set to "1", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure the operating system to disable kernel image loading.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

kernel.kexec_load_disabled = 1

Remove any configurations that conflict with the above from the following locations: 
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Load settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag gid: 'V-230266'
  tag rid: 'SV-230266r877463_rule'
  tag stig_id: 'RHEL-08-010372'
  tag fix_id: 'F-32910r858747_fix'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  else
    describe kernel_parameter('kernel.kexec_load_disabled') do
      its('value') { should eq 1 }
    end

    describe command('grep -r ^kernel.kexec_load_disabled /etc/sysctl.conf /etc/sysctl.d/*.conf') do
      its('stdout') { should match /kernel.kexec_load_disabled=1$/ }
    end
  end
end
