control 'SV-244552' do
  title 'RHEL 8 must not forward IPv4 source-routed packets by default.'
  desc  "Source-routed packets allow the source of the packet to suggest that
routers forward the packet along a different path than configured on the
router, which can be used to bypass network security measures. This requirement
applies only to the forwarding of source-routed traffic, such as when
forwarding is enabled and the system is functioning as a router."
  desc  'rationale', ''
  desc  'check', "
    Verify RHEL 8 does not accept IPv4 source-routed packets by default.

    Note: If IPv4 is disabled on the system, this requirement is Not Applicable.

    Check the value of the accept source route variable with the following
command:

    $ sudo sysctl net.ipv4.conf.default.accept_source_route

    net.ipv4.conf.default.accept_source_route = 0

    If the returned line does not have a value of \"0\", a line is not
returned, or the line is commented out, this is a finding.
  "
  desc  'fix', "
    Configure RHEL 8 to not forward IPv4 source-routed packets by default with
the following command:

    $ sudo sysctl -w net.ipv4.conf.default.accept_source_route=0

    If \"0\" is not the system's default value then add or update the following
line in the appropriate file under \"/etc/sysctl.d\":

    net.ipv4.conf.default.accept_source_route=0
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-244552'
  tag rid: 'SV-244552r743905_rule'
  tag stig_id: 'RHEL-08-040249'
  tag fix_id: 'F-47784r743904_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    describe kernel_parameter('net.ipv4.conf.default.accept_source_route') do
      its('value') { should eq 0 }
    end
  end
end

