control 'SV-230547' do
  title 'RHEL 8 must restrict exposed kernel pointer addresses access.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf'
  desc 'check', 'Verify RHEL 8 restricts exposed kernel pointer addresses access with the following commands:

$ sudo sysctl kernel.kptr_restrict

kernel.kptr_restrict = 1

If the returned line does not have a value of "1" or "2", or a line is not returned, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r kernel.kptr_restrict /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: kernel.kptr_restrict = 1

If "kernel.kptr_restrict" is not set to "1" or "2", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to restrict exposed kernel pointer addresses access by adding the following line to a file, in the "/etc/sysctl.d" directory:

kernel.kptr_restrict = 1

Remove any configurations that conflict with the above from the following locations: 
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

The system configuration files need to be reloaded for the changes to take effect. To reload the contents of the files, run the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230547'
  tag rid: 'SV-230547r858826_rule'
  tag stig_id: 'RHEL-08-040283'
  tag fix_id: 'F-33191r858825_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  else
    describe kernel_parameter('kernel.kptr_restrict') do
      its('value') { should eq 1 }
    end
  end
end
