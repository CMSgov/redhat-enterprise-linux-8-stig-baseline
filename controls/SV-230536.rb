control 'SV-230536' do
  title "RHEL 8 must not send Internet Control Message Protocol (ICMP)
redirects."
  desc  "ICMP redirect messages are used by routers to inform hosts that a more
direct route exists for a particular destination. These messages contain
information from the system's route table, possibly revealing portions of the
network topology.

    There are notable differences between Internet Protocol version 4 (IPv4)
and Internet Protocol version 6 (IPv6). There is only a directive to disable
sending of IPv4 redirected packets. Refer to RFC4294 for an explanation of
\"IPv6 Node Requirements\", which resulted in this difference between IPv4 and
IPv6.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify RHEL 8 does not IPv4 ICMP redirect messages.

    Note: If IPv4 is disabled on the system, this requirement is Not Applicable.

    Check the value of the \"all send_redirects\" variables with the following
command:

    $ sudo sysctl net.ipv4.conf.all.send_redirects

    net.ipv4.conf.all.send_redirects = 0

    If the returned line does not have a value of \"0\", or a line is not
returned, this is a finding.
  "
  desc  'fix', "
    Configure RHEL 8 to not allow interfaces to perform IPv4 ICMP redirects
with the following command:

    $ sudo sysctl -w net.ipv4.conf.all.send_redirects=0

    If \"0\" is not the system's default value then add or update the following
line in the appropriate file under \"/etc/sysctl.d\":

    net.ipv4.conf.all.send_redirects=0
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230536'
  tag rid: 'SV-230536r744037_rule'
  tag stig_id: 'RHEL-08-040220'
  tag fix_id: 'F-33180r568355_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    if input('ipv4_enabled')
      describe kernel_parameter('net.ipv4.conf.all.send_redirects') do
        its('value') { should eq 0 }
      end
    else
      impact 0.0
      describe 'IPv4 is disabled on the system, this requirement is Not Applicable.' do
        skip 'IPv4 is disabled on the system, this requirement is Not Applicable.'
      end
    end
  end
end
