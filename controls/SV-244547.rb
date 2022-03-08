control 'SV-244547' do
  title 'RHEL 8 must have the USBGuard installed.'
  desc  "Without authenticating devices, unidentified or unknown devices may be
introduced, thereby facilitating malicious activity.
    Peripherals include, but are not limited to, such devices as flash drives,
external storage, and printers.
    A new feature that RHEL 8 provides is the USBGuard software framework. The
USBguard-daemon is the main component of the USBGuard software framework. It
runs as a service in the background and enforces the USB device authorization
policy for all USB devices. The policy is defined by a set of rules using a
rule language described in the usbguard-rules.conf file. The policy and the
authorization state of USB devices can be modified during runtime using the
usbguard tool.

    The System Administrator (SA) must work with the site Information System
Security Officer (ISSO) to determine a list of authorized peripherals and
establish rules within the USBGuard software framework to allow only authorized
devices.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify USBGuard is installed on the operating system with the following
command:

    $ sudo yum list installed usbguard

    Installed Packages
    usbguard.x86_64                   0.7.8-7.el8             @ol8_appstream

    If the USBGuard package is not installed, ask the SA to indicate how
unauthorized peripherals are being blocked.
    If there is no evidence that unauthorized peripherals are being blocked
before establishing a connection, this is a finding.
  "
  desc  'fix', "
    Install the USBGuard package with the following command:

    $ sudo yum install usbguard.x86_64
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000378-GPOS-00163'
  tag gid: 'V-244547'
  tag rid: 'SV-244547r743890_rule'
  tag stig_id: 'RHEL-08-040139'
  tag fix_id: 'F-47779r743889_fix'
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    describe package('usbguard') do
      it { should be_installed }
    end
  end
end

