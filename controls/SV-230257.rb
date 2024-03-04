control 'SV-230257' do
  title 'RHEL 8 system commands must have mode 755 or less permissive.'
  desc 'If RHEL 8 were to allow any user to make changes to software
libraries, then those changes might be implemented without undergoing the
appropriate testing and approvals that are part of a robust change management
process.

    This requirement applies to RHEL 8 with software libraries that are
accessible and configurable, as in the case of interpreted languages. Software
libraries also include privileged programs that execute with escalated
privileges. Only qualified and authorized individuals will be allowed to obtain
access to information system components for purposes of initiating changes,
including upgrades and modifications.'
  desc 'check', 'Verify the system commands contained in the following directories have mode "755" or less permissive with the following command:

$ sudo find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -exec ls -l {} \\;

If any system commands are found to be group-writable or world-writable, this is a finding.'
  desc 'fix', 'Configure the system commands to be protected from unauthorized access.

Run the following command, replacing "[FILE]" with any system command with a mode more permissive than "755".

$ sudo chmod 755 [FILE]'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag gid: 'V-230257'
  tag rid: 'SV-230257r792862_rule'
  tag stig_id: 'RHEL-08-010300'
  tag fix_id: 'F-32901r792861_fix'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
  tag 'host', 'container'

  failing_files = command("find -L #{input('system_command_dirs').join(' ')} -perm /0022 -exec ls -d {} \\;").stdout.split("\n")

  describe 'System commands' do
    it "should have mode '0755' or less permissive" do
      expect(failing_files).to be_empty, "Files with excessive permissions:\n\t- #{failing_files.join("\n\t- ")}"
    end
  end
end
