control 'SV-244553' do
  title "RHEL 8 must ignore IPv4 Internet Control Message Protocol (ICMP)
redirect messages."
  desc  "ICMP redirect messages are used by routers to inform hosts that a more
direct route exists for a particular destination. These messages modify the
host's route table and are unauthenticated. An illicit ICMP redirect message
could result in a man-in-the-middle attack."
  desc  'rationale', ''
  desc  'check', "
    Verify RHEL 8 ignores IPv4 ICMP redirect messages.

    Note: If IPv4 is disabled on the system, this requirement is Not Applicable.

    Check the value of the \"accept_redirects\" variables with the following
command:

    $ sudo sysctl net.ipv4.conf.all.accept_redirects

    net.ipv4.conf.all.accept_redirects = 0

    If the returned line does not have a value of \"0\", a line is not
returned, or the line is commented out, this is a finding.
  "
  desc  'fix', "
    Configure RHEL 8 to ignore IPv4 ICMP redirect messages with the following
command:

    $ sudo sysctl -w net.ipv4.conf.all.accept_redirects=0

    If \"0\" is not the system's default value then add or update the following
line in the appropriate file under \"/etc/sysctl.d\":

    net.ipv4.conf.all.accept_redirects = 0
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-244553'
  tag rid: 'SV-244553r743908_rule'
  tag stig_id: 'RHEL-08-040279'
  tag fix_id: 'F-47785r743907_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    describe kernel_parameter('net.ipv4.conf.all.accept_redirects') do
      its('value') { should eq 0 }
    end
  end
end

