control 'SV-250317' do
  title 'RHEL 8 must not enable IPv4 packet forwarding unless the system is a router.'
  desc 'Routing protocol daemons are typically used on routers to exchange network topology information with other routers. If this software is used when not required, system network information may be unnecessarily transmitted across the network.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf'
  desc 'check', 'Verify RHEL 8 is not performing IPv4 packet forwarding, unless the system is a router.

Check that IPv4 forwarding is disabled using the following command:

$ sudo sysctl net.ipv4.conf.all.forwarding

net.ipv4.conf.all.forwarding = 0
If the IPv4 forwarding value is not "0" and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv4.conf.all.forwarding /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.ipv4.conf.all.forwarding = 0

If "net.ipv4.conf.all.forwarding" is not set to "0", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to not allow IPv4 packet forwarding, unless the system is a router.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv4.conf.all.forwarding=0

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
  tag check_id: 'C-53751r833382_chk'
  tag severity: 'medium'
  tag gid: 'V-250317'
  tag rid: 'SV-250317r858808_rule'
  tag stig_id: 'RHEL-08-040259'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-53705r858807_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
