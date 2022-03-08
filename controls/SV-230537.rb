control 'SV-230537' do
  title "RHEL 8 must not respond to Internet Control Message Protocol (ICMP)
echoes sent to a broadcast address."
  desc  "Responding to broadcast ICMP echoes facilitates network mapping and
provides a vector for amplification attacks.

    There are notable differences between Internet Protocol version 4 (IPv4)
and Internet Protocol version 6 (IPv6). IPv6 does not implement the same method
of broadcast as IPv4. Instead, IPv6 uses multicast addressing to the all-hosts
multicast group. Refer to RFC4294 for an explanation of \"IPv6 Node
Requirements\", which resulted in this difference between IPv4 and IPv6.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify RHEL 8 does not respond to ICMP echoes sent to a broadcast address.

    Note: If IPv4 is disabled on the system, this requirement is Not Applicable.
    Check the value of the \"icmp_echo_ignore_broadcasts\" variable with the
following command:

    $ sudo sysctl net.ipv4.icmp_echo_ignore_broadcasts

    net.ipv4.icmp_echo_ignore_broadcasts = 1

    If the returned line does not have a value of \"1\", a line is not
returned, or the retuned line is commented out, this is a finding.
  "
  desc  'fix', "
    Configure RHEL 8 to not respond to IPv4 ICMP echoes sent to a broadcast
address with the following command:

    $ sudo sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1

    If \"1\" is not the system's default value then add or update the following
line in the appropriate file under \"/etc/sysctl.d\":

    net.ipv4.icmp_echo_ignore_broadcasts=1
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230537'
  tag rid: 'SV-230537r744039_rule'
  tag stig_id: 'RHEL-08-040230'
  tag fix_id: 'F-33181r568358_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']


  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    if input('ipv4_enabled')
      describe kernel_parameter('net.ipv4.icmp_echo_ignore_broadcasts') do
        its('value') { should eq 1 }
      end
    else
      impact 0.0
      describe 'IPv4 is disabled on the system, this requirement is Not Applicable.' do
        skip 'IPv4 is disabled on the system, this requirement is Not Applicable.'
      end
    end
  end
end
