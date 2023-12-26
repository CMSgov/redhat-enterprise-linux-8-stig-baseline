# frozen_string_literal: true

control 'SV-244548' do
  title 'RHEL 8 must enable the USBGuard.'
  desc 'Without authenticating devices, unidentified or unknown devices may be
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
devices.'
  desc 'check', 'Verify the operating system has enabled the use of the USBGuard with the
following command:

    $ sudo systemctl status usbguard.service

    usbguard.service - USBGuard daemon
    Loaded: loaded (/usr/lib/systemd/system/usbguard.service; enabled; vendor
preset: disabled)
    Active: active (running)

    If the usbguard.service is not enabled and active, ask the SA to indicate
how unauthorized peripherals are being blocked.
    If there is no evidence that unauthorized peripherals are being blocked
before establishing a connection, this is a finding.'
  desc 'fix', 'Configure the operating system to enable the blocking of unauthorized
peripherals with the following commands:

    $ sudo systemctl enable usbguard.service

    $ sudo systemctl start usbguard.service

    Note: Enabling and starting usbguard without properly configuring it for an
individual system will immediately prevent any access over a usb device such as
a keyboard or mouse'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000378-GPOS-00163'
  tag gid: 'V-244548'
  tag rid: 'SV-244548r854077_rule'
  tag stig_id: 'RHEL-08-040141'
  tag fix_id: 'F-47780r743892_fix'
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  else
    describe service('usbguard') do
      it { should be_running }
      it { should be_enabled }
    end
  end
end
