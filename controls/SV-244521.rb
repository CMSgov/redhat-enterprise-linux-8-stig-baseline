control 'SV-244521' do
  title "RHEL 8 operating systems booted with United Extensible Firmware
Interface (UEFI) must require a unique superusers name upon booting into
single-user mode and maintenance."
  desc  "If the system does not require valid authentication before it boots
into single-user or maintenance mode, anyone who invokes single-user or
maintenance mode is granted privileged access to all files on the system. GRUB
2 is the default boot loader for RHEL 8 and is designed to require a password
to boot into single-user mode or make modifications to the boot menu."
  desc  'rationale', ''
  desc  'check', "
    For systems that use BIOS, this is Not Applicable.

    Verify that a unique name is set as the \"superusers\" account:

    $ sudo grep -iw \"superusers\" /boot/efi/EFI/redhat/grub.cfg
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

    $ sudo grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag gid: 'V-244521'
  tag rid: 'SV-244521r743812_rule'
  tag stig_id: 'RHEL-08-010141'
  tag fix_id: 'F-47753r743811_fix'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    if file('/sys/firmware/efi').exist?
      describe parse_config_file(input('grub_uefi_main_cfg')) do
        its('set superusers') { should cmp '"root"' }
      end
    else
      impact 0.0
      describe 'System running BIOS' do
        skip 'The System is running BIOS, this control is Not Applicable.'
      end
    end
  end
end

