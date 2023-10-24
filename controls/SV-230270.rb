control 'SV-230270' do
  title 'RHEL 8 must prevent kernel profiling by unprivileged users.'
  desc 'Preventing unauthorized information transfers mitigates the risk of information, including encrypted representations of information, produced by the actions of prior users/roles (or the actions of processes acting on behalf of prior users/roles) from being available to any current users/roles (or current processes) that obtain access to shared system resources (e.g., registers, main memory, hard disks) after those resources have been released back to information systems. The control of information in shared resources is also commonly referred to as object reuse and residual information protection.

This requirement generally applies to the design of an information technology product, but it can also apply to the configuration of particular information system components that are, or use, such products. This can be verified by acceptance/validation processes in DoD or other government agencies.

There may be shared resources with configurable protections (e.g., files in storage) that may be assessed on specific information system components.

Setting the kernel.perf_event_paranoid kernel parameter to "2" prevents attackers from gaining additional system information as a non-privileged user.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf'
  desc 'check', 'Verify the operating system is configured to prevent kernel profiling by unprivileged users with the following commands:

Check the status of the kernel.perf_event_paranoid kernel parameter.

$ sudo sysctl kernel.perf_event_paranoid

kernel.perf_event_paranoid = 2

If "kernel.perf_event_paranoid" is not set to "2" or is missing, this is a finding.

Check that the configuration files are present to enable this kernel parameter.

$ sudo grep -r kernel.perf_event_paranoid /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf:kernel.perf_event_paranoid = 2

If "kernel.perf_event_paranoid" is not set to "2", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure the operating system to prevent kernel profiling by unprivileged users.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

kernel.perf_event_paranoid = 2

Remove any configurations that conflict with the above from the following locations: 
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Load settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag gid: 'V-230270'
  tag rid: 'SV-230270r858758_rule'
  tag stig_id: 'RHEL-08-010376'
  tag fix_id: 'F-32914r858757_fix'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  else
    describe kernel_parameter('kernel.perf_event_paranoid') do
      its('value') { should eq 2 }
    end

    describe parse_config(command('grep -rh ^kernel.perf_event_paranoid /etc/sysctl.conf /etc/sysctl.d/*.conf').stdout.strip) do
      its(['kernel.perf_event_paranoid']) { should cmp 2 }
    end
  end
end
