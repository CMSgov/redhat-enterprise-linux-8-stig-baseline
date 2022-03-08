control 'SV-230278' do
  title 'RHEL 8 must disable virtual syscalls.'
  desc  "Syscalls are special routines in the Linux kernel, which userspace
applications ask to do privileged tasks.  Invoking a system call is an
expensive operation because the processor must interrupt the currently
executing task and switch context to kernel mode and then back to userspace
after the system call completes.  Virtual Syscalls map into user space a page
that contains some variables and the implementation of some system calls.  This
allows the system calls to be executed in userspace to alleviate the context
switching expense.

    Virtual Syscalls provide an opportunity of attack for a user who has
control of the return instruction pointer.  Disabling vsyscalls help to prevent
return oriented programming (ROP) attacks via buffer overflows and overruns. If
the system intends to run containers based on RHEL 6 components, then virtual
syscalls will need enabled so the components function properly.


  "
  desc  'rationale', ''
  desc  'check', "
    Verify that GRUB 2 is configured to disable vsyscalls with the following
commands:

    Check that the current GRUB 2 configuration disables vsyscalls:

    $ sudo grub2-editenv - list | grep vsyscall

    kernelopts=root=/dev/mapper/rhel-root ro crashkernel=auto
resume=/dev/mapper/rhel-swap rd.lvm.lv=rhel/root rd.lvm.lv=rhel/swap rhgb quiet
fips=1 page_poison=1 vsyscall=none audit=1 audit_backlog_limit=8192
boot=UUID=8d171156-cd61-421c-ba41-1c021ac29e82

    If \"vsyscall\" is not set to \"none\" or is missing, this is a finding.

    Check that vsyscalls are disabled by default to persist in kernel updates:

    $ sudo grep vsyscall /etc/default/grub

    GRUB_CMDLINE_LINUX=\"vsyscall=none\"

    If \"vsyscall\" is not set to \"none\", is missing or commented out and is
not documented with the Information System Security Officer (ISSO) as an
operational requirement, this is a finding.
  "
  desc  'fix', "
    Document the use of vsyscalls with the ISSO as an operational requirement
or disable them with the following command:

    $ sudo grubby --update-kernel=ALL --args=\"vsyscall=none\"

    Add or modify the following line in \"/etc/default/grub\" to ensure the
configuration survives kernel updates:

    GRUB_CMDLINE_LINUX=\"vsyscall=none\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag satisfies: ['SRG-OS-000134-GPOS-00068', 'SRG-OS-000433-GPOS-00192']
  tag gid: 'V-230278'
  tag rid: 'SV-230278r743948_rule'
  tag stig_id: 'RHEL-08-010422'
  tag fix_id: 'F-32922r743947_fix'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']

  grub_stdout = command('grub2-editenv - list').stdout

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    describe parse_config(grub_stdout) do
      its('kernelopts') { should match /vsyscall=none/ }
    end
  
    describe parse_config_file('/etc/default/grub') do
      its('GRUB_CMDLINE_LINUX') { should match /vsyscall=none/ }
    end
  end
end
