control 'SV-244522' do
  title "RHEL 8 operating systems booted with a BIOS must require  a unique
superusers name upon booting into single-user and maintenance modes."
  desc  "If the system does not require valid authentication before it boots
into single-user or maintenance mode, anyone who invokes single-user or
maintenance mode is granted privileged access to all files on the system. GRUB
2 is the default boot loader for RHEL 8 and is designed to require a password
to boot into single-user mode or make modifications to the boot menu."
  desc  'rationale', ''
  desc  'check', "
    For systems that use UEFI, this is Not Applicable.

    Verify that a unique name is set as the \"superusers\" account:

    $ sudo grep -iw \"superusers\" /boot/grub2/grub.cfg
    set superusers=\"[someuniquestringhere]\"
    export superusers

    If \"superusers\" is not set to a unique name or is missing a name, this is
a finding.
  "
  desc  'fix', "
    Configure the system to have a unique name for the grub superusers account.

    Edit the /etc/grub.d/01_users file and add or modify the following lines:

    set superusers=\"[someuniquestringhere]\"
    export superusers
    password_pbkdf2 [someuniquestringhere] ${GRUB2_PASSWORD}

    Generate a new grub.cfg file with the following command:

    $ sudo grub2-mkconfig -o /boot/grub2/grub.cfg
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag gid: 'V-244522'
  tag rid: 'SV-244522r743815_rule'
  tag stig_id: 'RHEL-08-010149'
  tag fix_id: 'F-47754r743814_fix'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    if file('/sys/firmware/efi').exist?
      impact 0.0
      describe 'System running UEFI' do
        skip 'The System is running UEFI, this control is Not Applicable.'
      end
    else
      describe parse_config_file(input('grub_main_cfg')) do
        its('set superusers') { should_not be_empty }
      end
    end
  end
end

