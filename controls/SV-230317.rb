control 'SV-230317' do
  title 'Executable search paths within the initialization files of all local
interactive RHEL 8 users must only contain paths that resolve to the system
default or the users home directory.'
  desc "The executable search path (typically the PATH environment variable)
contains a list of directories for the shell to search to find executables. If
this path includes the current working directory (other than the user's home
directory), executables in these directories may be executed instead of system
commands. This variable is formatted as a colon-separated list of directories.
If there is an empty entry, such as a leading or trailing colon or two
consecutive colons, this is interpreted as the current working directory. If
deviations from the default system search path for the local interactive user
are required, they must be documented with the Information System Security
Officer (ISSO)."
  desc 'check', 'Verify that all local interactive user initialization file executable search path statements do not contain statements that will reference a working directory other than user home directories with the following commands:

$ sudo grep -i path= /home/*/.*

/home/[localinteractiveuser]/.bash_profile:PATH=$PATH:$HOME/.local/bin:$HOME/bin

If any local interactive user initialization files have executable search path statements that include directories outside of their home directory and is not documented with the ISSO as an operational requirement, this is a finding.'
  desc 'fix', 'Edit the local interactive user initialization files to change any PATH
variable statements that reference directories other than their home directory.

    If a local interactive user requires path variables to reference a
directory owned by the application, it must be documented with the ISSO.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230317'
  tag rid: 'SV-230317r792896_rule'
  tag stig_id: 'RHEL-08-010690'
  tag fix_id: 'F-32961r567698_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  exempt_home_users = input('exempt_home_users')
  non_interactive_shells = input('non_interactive_shells')

  ignore_shells = non_interactive_shells.join('|')

  findings = Set[]
  users.where { !shell.match(ignore_shells) && (uid >= 1000 || uid == 0) }.entries.each do |user_info|
    next if exempt_home_users.include?(user_info.username.to_s)
    grep_results = command("grep -i path --exclude=\".bash_history\" #{user_info.home}/.*").stdout.split('\\n')
    grep_results.each do |result|
      result.slice! 'PATH='
      # Case when last value in exec search path is :
      result += ' ' if result[-1] == ':'
      result.slice! '$PATH:'
      result.gsub! '$HOME', user_info.home.to_s
      result.gsub! '~', user_info.home.to_s
      line_arr = result.split(':')
      line_arr.delete_at(0)
      line_arr.each do |line|
        # Don't run test on line that exports PATH and is not commented out
        next unless !line.start_with?('export') && !line.start_with?('#')
        # Case when :: found in exec search path or : found at beginning
        if line.strip.empty?
          curr_work_dir = command('pwd').stdout.delete("\n")
          line = curr_work_dir if curr_work_dir.start_with?(user_info.home.to_s)
        end
        # This will fail if non-home directory found in path
        findings.add(line) unless line.start_with?(user_info.home)
      end
    end
  end
  describe.one do
    describe etc_fstab do
      its('home_mount_options') { should include 'nosuid' }
    end
    describe 'Initialization files that include executable search paths that include directories outside their home directories' do
      subject { findings.to_a }
      it { should be_empty }
    end
  end
end
