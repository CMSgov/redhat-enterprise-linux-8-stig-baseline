control 'SV-230279' do
  title 'RHEL 8 must clear SLUB/SLAB objects to prevent use-after-free attacks.'
  desc  "Some adversaries launch attacks with the intent of executing code in
non-executable regions of memory or in memory locations that are prohibited.
Security safeguards employed to protect memory include, for example, data
execution prevention and address space layout randomization. Data execution
prevention safeguards can be either hardware-enforced or software-enforced with
hardware providing the greater strength of mechanism.

    Poisoning writes an arbitrary value to freed pages, so any modification or
reference to that page after being freed or before being initialized will be
detected and prevented. This prevents many types of use-after-free
vulnerabilities at little performance cost. Also prevents leak of data and
detection of corrupted memory.

    SLAB objects are blocks of physically-contiguous memory.  SLUB is the
unqueued SLAB allocator.


  "
  desc  'rationale', ''
  desc  'check', "
    Verify that GRUB 2 is configured to enable poisoning of SLUB/SLAB objects
to mitigate use-after-free vulnerabilities with the following commands:

    Check that the current GRUB 2 configuration has poisoning of SLUB/SLAB
objects enabled:

    $ sudo grub2-editenv - list | grep slub_debug

    kernelopts=root=/dev/mapper/rhel-root ro crashkernel=auto
resume=/dev/mapper/rhel-swap rd.lvm.lv=rhel/root rd.lvm.lv=rhel/swap rhgb quiet
fips=1 slub_debug=P page_poison=1 vsyscall=none audit=1
audit_backlog_limit=8192 boot=UUID=8d171156-cd61-421c-ba41-1c021ac29e82

    If \"slub_debug\" is not set to \"P\" or is missing, this is a finding.

    Check that poisoning of SLUB/SLAB objects is enabled by default to persist
in kernel updates:

    $ sudo grep slub_debug /etc/default/grub

    GRUB_CMDLINE_LINUX=\"slub_debug=P\"

    If \"slub_debug\" is not set to \"P\", is missing or commented out, this is
a finding.
  "
  desc 'fix', "
    Configure RHEL 8 to enable poisoning of SLUB/SLAB objects with the
following commands:

    $ sudo grubby --update-kernel=ALL --args=\"slub_debug=P\"

    Add or modify the following line in \"/etc/default/grub\" to ensure the
configuration survives kernel updates:

    GRUB_CMDLINE_LINUX=\"slub_debug=P\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag satisfies: %w(SRG-OS-000134-GPOS-00068 SRG-OS-000433-GPOS-00192)
  tag gid: 'V-230279'
  tag rid: 'SV-230279r627750_rule'
  tag stig_id: 'RHEL-08-010423'
  tag fix_id: 'F-32923r567584_fix'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']

  grub_stdout = command('grub2-editenv - list').stdout

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  else
    describe parse_config(grub_stdout) do
      its('kernelopts') { should match /slub_debug=P/ }
    end

    describe parse_config_file('/etc/default/grub') do
      its('GRUB_CMDLINE_LINUX') { should match /slub_debug=P/ }
    end
  end
end
