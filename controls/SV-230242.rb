control 'SV-230242' do
  title "All RHEL 8 public directories must be owned by root or a system
account to prevent unauthorized and unintended information transferred via
shared system resources."
  desc  "Preventing unauthorized information transfers mitigates the risk of
information, including encrypted representations of information, produced by
the actions of prior users/roles (or the actions of processes acting on behalf
of prior users/roles) from being available to any current users/roles (or
current processes) that obtain access to shared system resources (e.g.,
registers, main memory, hard disks) after those resources have been released
back to information systems. The control of information in shared resources is
also commonly referred to as object reuse and residual information protection.

    This requirement generally applies to the design of an information
technology product, but it can also apply to the configuration of particular
information system components that are, or use, such products. This can be
verified by acceptance/validation processes in DoD or other government agencies.

    There may be shared resources with configurable protections (e.g., files in
storage) that may be assessed on specific information system components.
  "
  desc  'rationale', ''
  desc  'check', "
    Check to see that all public directories are owned by root or a system
account with the following command:

    $ sudo find / -type d -perm -0002 -exec ls -lLd {} \\;

    drwxrwxrwxt 7 root root 4096 Jul 26 11:19 /tmp

    If any of the returned directories are not owned by root or a system
account, this is a finding.
  "
  desc 'fix', "
    Configure all public directories to be owned by root or a system account to
prevent unauthorized and unintended information transferred via shared system
resources.

    Set the owner of all public directories as root or a system account using
the command, replace \"[Public Directory]\" with any directory path not owned
by root or a system account:

    $ sudo chown root [Public Directory]
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag gid: 'V-230242'
  tag rid: 'SV-230242r627750_rule'
  tag stig_id: 'RHEL-08-010180'
  tag fix_id: 'F-32886r567473_fix'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']

  allowed_accounts = (input('known_system_accounts') + ['root']).uniq
  files = command('find / -type d -perm -0002 -exec ls -d {} \\;').stdout.split

  if files.empty?
    describe 'List of all public directories on the target' do
      subject { files }
      it { should be_empty }
    end
  else
    files.each do |file|
      describe file(file) do
        its('owner') { should be_in allowed_accounts }
        its('group') { should be_in allowed_accounts }
      end
    end
  end
end
