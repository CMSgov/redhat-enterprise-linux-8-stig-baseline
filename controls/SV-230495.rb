control 'SV-230495' do
  title 'RHEL 8 must disable the controller area network (CAN) protocol.'
  desc  "It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

    Failing to disconnect unused protocols can result in a system compromise.

    The Controller Area Network (CAN) is a serial communications protocol,
which was initially developed for automotive and is now also used in marine,
industrial, and medical applications. Disabling CAN protects the system against
exploitation of any flaws in its implementation.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the operating system disables the ability to load the CAN protocol
kernel module.

    $ sudo grep -ri CAN /etc/modprobe.d/* | grep -i \"/bin/true\"

    install CAN /bin/true

    If the command does not return any output, or the line is commented out,
and use of the CAN protocol is not documented with the Information System
Security Officer (ISSO) as an operational requirement, this is a finding.

    Verify the operating system disables the ability to use the CAN protocol.

    Check to see if the CAN protocol is disabled with the following command:

    $ sudo grep -ri CAN /etc/modprobe.d/* | grep -i \"blacklist\"

    blacklist CAN

    If the command does not return any output or the output is not \"blacklist
CAN\", and use of the CAN protocol is not documented with the Information
System Security Officer (ISSO) as an operational requirement, this is a finding.
  "
  desc 'fix', "
    Configure the operating system to disable the ability to use the CAN
protocol kernel module.

    Add or update the following lines in the file
\"/etc/modprobe.d/blacklist.conf\":

    install CAN /bin/true
    blacklist CAN

    Reboot the system for the settings to take effect.
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag gid: 'V-230495'
  tag rid: 'SV-230495r627750_rule'
  tag stig_id: 'RHEL-08-040022'
  tag fix_id: 'F-33139r568232_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    describe kernel_module('CAN') do
      it { should be_disabled }
      it { should be_blacklisted }
    end
  end
end
