control 'SV-230549' do
  title 'RHEL 8 must use reverse path filtering on all IPv4 interfaces.'
  desc  "It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

    Enabling reverse path filtering drops packets with source addresses that
are not routable.  There is not an equivalent filter for IPv6 traffic.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify RHEL 8 uses reverse path filtering on all IPv4 interfaces with the
following commands:

    $ sudo sysctl net.ipv4.conf.all.rp_filter

    net.ipv4.conf.all.rp_filter = 1

    If the returned line does not have a value of \"1\", or a line is not
returned, this is a finding.
  "
  desc 'fix', "
    Configure RHEL 8 to use reverse path filtering on all IPv4 interfaces by
adding the following line to a file in the \"/etc/sysctl.d\" directory:

    net.ipv4.conf.all.rp_filter = 1

    The system configuration files need to be reloaded for the changes to take
effect. To reload the contents of the files, run the following command:

    $ sudo sysctl --system
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230549'
  tag rid: 'SV-230549r627750_rule'
  tag stig_id: 'RHEL-08-040285'
  tag fix_id: 'F-33193r568394_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    describe kernel_parameter('net.ipv4.conf.all.rp_filter') do
      its('value') { should eq 1 }
    end
  end
end
