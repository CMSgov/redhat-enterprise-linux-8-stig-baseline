control 'SV-230538' do
  title 'RHEL 8 must not forward IPv6 source-routed packets.'
  desc  "Source-routed packets allow the source of the packet to suggest that
routers forward the packet along a different path than configured on the
router, which can be used to bypass network security measures. This requirement
applies only to the forwarding of source-routed traffic, such as when
forwarding is enabled and the system is functioning as a router."
  desc  'rationale', ''
  desc  'check', "
    Verify RHEL 8 does not accept IPv6 source-routed packets.

    Note: If IPv6 is disabled on the system, this requirement is Not Applicable.

    Check the value of the accept source route variable with the following
command:

    $ sudo sysctl net.ipv6.conf.all.accept_source_route

    net.ipv6.conf.all.accept_source_route = 0

    If the returned line does not have a value of \"0\", a line is not
returned, or the line is commented out, this is a finding.
  "
  desc  'fix', "
    Configure RHEL 8 to not forward IPv6 source-routed packets with the
following command:

    $ sudo sysctl -w net.ipv6.conf.all.accept_source_route=0

    If \"0\" is not the system's all value then add or update the following
line in the appropriate file under \"/etc/sysctl.d\":

    net.ipv6.conf.all.accept_source_route=0
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230538'
  tag rid: 'SV-230538r744042_rule'
  tag stig_id: 'RHEL-08-040240'
  tag fix_id: 'F-33182r744041_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']


  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    if input('ipv6_enabled')
      describe kernel_parameter('net.ipv6.conf.default.accept_source_route') do
        its('value') { should eq 0 }
      end
    else
      impact 0.0
      describe 'IPv6 is disabled on the system, this requirement is Not Applicable.' do
        skip 'IPv6 is disabled on the system, this requirement is Not Applicable.'
      end
    end
  end
end

