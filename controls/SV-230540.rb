control 'SV-230540' do
  title "RHEL 8 must not be performing packet forwarding unless the system is a
router."
  desc  "Routing protocol daemons are typically used on routers to exchange
network topology information with other routers. If this software is used when
not required, system network information may be unnecessarily transmitted
across the network."
  desc  'rationale', ''
  desc  'check', "
    Verify RHEL 8 is not performing packet forwarding, unless the system is a
router.

    Note: If either IPv4 or IPv6 is disabled on the system, this requirement
only applies to the active internet protocol version.

    Check to see if IP forwarding is enabled using the following commands:

    $ sudo sysctl  net.ipv4.ip_forward

    net.ipv4.ip_forward = 0

    $ sudo sysctl net.ipv6.conf.all.forwarding

    net.ipv6.conf.all.forwarding = 0

    If IP forwarding value is not \"0\" and is not documented with the
Information System Security Officer (ISSO) as an operational requirement, this
is a finding.
  "
  desc 'fix', "
    Configure RHEL 8 to not allow packet forwarding, unless the system is a
router with the following commands:

    $ sudo sysctl -w net.ipv4.ip_forward=0

    $ sudo sysctl -w net.ipv6.conf.all.forwarding=0

    If \"0\" is not the system's default value then add or update the following
lines in the appropriate file under \"/etc/sysctl.d\":

    net.ipv4.ip_forward=0

    net.ipv6.conf.all.forwarding=0
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230540'
  tag rid: 'SV-230540r627750_rule'
  tag stig_id: 'RHEL-08-040260'
  tag fix_id: 'F-33184r568367_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    describe kernel_parameter('net.ipv4.ip_forward') do
      its('value') { should eq 0 }
    end
    if input('ipv6_enabled')
      describe kernel_parameter('net.ipv6.conf.all.forwarding') do
        its('value') { should eq 0 }
      end
    end
  end
end
