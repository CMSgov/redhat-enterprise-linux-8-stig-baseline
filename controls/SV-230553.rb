control 'SV-230553' do
  title "The graphical display manager must not be installed on RHEL 8 unless
approved."
  desc  "Internet services that are not required for system or application
processes must not be active to decrease the attack surface of the system.
Graphical display managers have a long history of security vulnerabilities and
must not be used, unless approved and documented."
  desc  'rationale', ''
  desc  'check', "
    Verify that the system is configured to boot to the command line:

    $ systemctl get-default
    multi-user.target

    If the system default target is not set to \"multi-user.target\" and the
Information System Security Officer (ISSO) lacks a documented requirement for a
graphical user interface, this is a finding.

    Verify that a graphical user interface is not installed:

    $ rpm -qa | grep xorg | grep server

    Ask the System Administrator if use of a graphical user interface is an
operational requirement.

    If the use of a graphical user interface on the system is not documented
with the ISSO, this is a finding.
  "
  desc 'fix', "
    Document the requirement for a graphical user interface with the ISSO or
reinstall the operating system without the graphical user interface. If
reinstallation is not feasible, then continue with the following procedure:

    Open an SSH session and enter the following commands:

    $ sudo systemctl set-default multi-user.target

    $ sudo yum remove xorg-x11-server-Xorg xorg-x11-server-common
xorg-x11-server-utils xorg-x11-server-Xwayland

    A reboot is required for the changes to take effect.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230553'
  tag rid: 'SV-230553r646886_rule'
  tag stig_id: 'RHEL-08-040320'
  tag fix_id: 'F-33197r646885_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe command('systemctl get-default') do
    its('stdout.strip') { should eq 'multi-user.target' }
  end
  describe package('xorg-x11-server-common') do
    it { should_not be_installed }
  end
  describe package('xorg-x11-server-Xorg') do
    it { should_not be_installed }
  end
  describe package('xorg-x11-server-utils') do
    it { should_not be_installed }
  end
  describe package('xorg-x11-server-Xwayland') do
    it { should_not be_installed }
  end
end
