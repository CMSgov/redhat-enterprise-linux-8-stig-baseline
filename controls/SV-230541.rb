control 'SV-230541' do
  title 'RHEL 8 must not accept router advertisements on all IPv6 interfaces.'
  desc 'Routing protocol daemons are typically used on routers to exchange network topology information with other routers. If this software is used when not required, system network information may be unnecessarily transmitted across the network.

An illicit router advertisement message could result in a man-in-the-middle attack.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf'
  desc 'check', 'Verify RHEL 8 does not accept router advertisements on all IPv6 interfaces, unless the system is a router.

Note: If IPv6 is disabled on the system, this requirement is not applicable.

Check to see if router advertisements are not accepted by using the following command:

$ sudo sysctl  net.ipv6.conf.all.accept_ra

net.ipv6.conf.all.accept_ra = 0

If the "accept_ra" value is not "0" and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv6.conf.all.accept_ra /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.ipv6.conf.all.accept_ra = 0

If "net.ipv6.conf.all.accept_ra" is not set to "0", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to not accept router advertisements on all IPv6 interfaces unless the system is a router.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv6.conf.all.accept_ra=0

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
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230541'
  tag rid: 'SV-230541r858812_rule'
  tag stig_id: 'RHEL-08-040261'
  tag fix_id: 'F-33185r858811_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  elsif input('ipv6_enabled')
    describe kernel_parameter('net.ipv6.conf.all.accept_ra') do
      its('value') { should eq 0 }
    end
  else
    impact 0.0
    describe 'IPv6 not enabled' do
      skip 'IPv6 is not enabled, this control is Not Applicable.'
    end
  end
end
