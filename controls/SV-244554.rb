control 'SV-244554' do
  title 'RHEL 8 must enable hardening for the Berkeley Packet Filter
Just-in-time compiler.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Enabling hardening for the Berkeley Packet Filter (BPF) Just-in-time (JIT) compiler aids in mitigating JIT spraying attacks. Setting the value to "2" enables JIT hardening for all users.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf'
  desc 'check', 'Verify RHEL 8 enables hardening for the BPF JIT with the following commands:

$ sudo sysctl net.core.bpf_jit_harden

net.core.bpf_jit_harden = 2

If the returned line does not have a value of "2", or a line is not returned, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.core.bpf_jit_harden /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.core.bpf_jit_harden = 2

If "net.core.bpf_jit_harden" is not set to "2", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to enable hardening for the BPF JIT compiler by adding the following line to a file, in the "/etc/sysctl.d" directory:

net.core.bpf_jit_harden = 2

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
  tag gid: 'V-244554'
  tag rid: 'SV-244554r858832_rule'
  tag stig_id: 'RHEL-08-040286'
  tag fix_id: 'F-47786r858831_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  else
    describe kernel_parameter('net.core.bpf_jit_harden') do
      its('value') { should eq 2 }
    end
  end
end
