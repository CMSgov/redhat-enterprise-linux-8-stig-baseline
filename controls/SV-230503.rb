control 'SV-230503' do
  title 'RHEL 8 must be configured to disable USB mass storage.'
  desc  "USB mass storage permits easy introduction of unknown devices, thereby
facilitating malicious activity.


  "
  desc  'rationale', ''
  desc  'check', "
    Verify the operating system disables the ability to load the USB Storage
kernel module.

    $ sudo grep -r usb-storage /etc/modprobe.d/* | grep -i \"/bin/true\"

    install usb-storage /bin/true

    If the command does not return any output, or the line is commented out,
and use of USB Storage is not documented with the Information System Security
Officer (ISSO) as an operational requirement, this is a finding.

    Verify the operating system disables the ability to use USB mass storage
devices.

    Check to see if USB mass storage is disabled with the following command:

    $ sudo grep usb-storage /etc/modprobe.d/* | grep -i \"blacklist\"

    blacklist usb-storage

    If the command does not return any output or the output is not \"blacklist
usb-storage\", and use of USB storage devices is not documented with the
Information System Security Officer (ISSO) as an operational requirement, this
is a finding.
  "
  desc 'fix', "
    Configure the operating system to disable the ability to use the USB
Storage kernel module.

    Create a file under \"/etc/modprobe.d\" with the following command:

    $ sudo touch /etc/modprobe.d/usb-storage.conf

    Add the following line to the created file:

    install usb-storage /bin/true

    Configure the operating system to disable the ability to use USB mass
storage devices.

    $ sudo vi /etc/modprobe.d/blacklist.conf

    Add or update the line:

    blacklist usb-storage
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag satisfies: %w(SRG-OS-000114-GPOS-00059 SRG-OS-000378-GPOS-00163)
  tag gid: 'V-230503'
  tag rid: 'SV-230503r627750_rule'
  tag stig_id: 'RHEL-08-040080'
  tag fix_id: 'F-33147r568256_fix'
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    describe kernel_module('usb_storage') do
      it { should be_disabled }
      it { should be_blacklisted }
    end
  end
end
