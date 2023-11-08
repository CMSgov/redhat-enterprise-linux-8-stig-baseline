control 'SV-230384' do
  title "RHEL 8 must set the umask value to 077 for all local interactive user
accounts."
  desc  "The umask controls the default access mode assigned to newly created
files. A umask of 077 limits new files to mode 600 or less permissive. Although
umask can be represented as a four-digit number, the first digit representing
special access modes is typically ignored or required to be \"0\". This
requirement applies to the globally configured system defaults and the local
interactive user defaults for each account on the system."
  desc  'rationale', ''
  desc  'check', "
    Verify that the default umask for all local interactive users is \"077\".

    Identify the locations of all local interactive user home directories by
looking at the \"/etc/passwd\" file.

    Check all local interactive user initialization files for interactive users
with the following command:

    Note: The example is for a system that is configured to create users home
directories in the \"/home\" directory.

    # grep -i umask /home/*/.*

    If any local interactive user initialization files are found to have a
umask statement that has a value less restrictive than \"077\", this is a
finding.
  "
  desc 'fix', "
    Remove the umask statement from all local interactive user's initialization
files.

    If the account is for an application, the requirement for a umask less
restrictive than \"077\" can be documented with the Information System Security
Officer, but the user agreement for access to the account must specify that the
local interactive user must log on to their account first and then switch the
user to the application account with the correct option to gain the account's
environment variables.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00228'
  tag gid: 'V-230384'
  tag rid: 'SV-230384r627750_rule'
  tag stig_id: 'RHEL-08-020352'
  tag fix_id: 'F-33028r567899_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  ignore_shells = input('non_interactive_shells').join('|')

  # Get home directory for users with UID >= 1000 or UID == 0 and support interactive logins.
  findings = Set[]
  dotfiles = Set[]
  umasks = {}
  umask_findings = Set[]

  uid_min = login_defs.UID_MIN.to_i

  interactive_users = users.where { !shell.match(ignore_shells) && (uid >= uid_min || uid == 0) }.entries

  # For each user, build and execute a find command that identifies initialization files
  # in a user's home directory.
  interactive_users.each do |u|
    # Only check if the home directory is local
    is_local = command("df -l #{u.home}").exit_status

    if is_local == 0
      # Get user's initialization files
      dotfiles += command("find #{u.home} -xdev -maxdepth 2 ( -name '.*' ! -name '.bash_history' ) -type f").stdout.split("\n")

      # Get user's umask
      umasks.store(u.username, command("su -c 'umask' -l #{u.username}").stdout.chomp("\n"))

      # Check all local initialization files to see whether or not they are less restrictive than 077.
      dotfiles.each do |df|
        findings += df if file(df).more_permissive_than?('0077')
      end

      # Check umask for all interactive users
      umasks.each do |key, value|
        max_mode = '0077'.to_i(8)
        inv_mode = 0777 ^ max_mode
        umask_findings += key if inv_mode & value.to_i(8) != 0
      end
    else
      describe 'This control skips non-local filesystems' do
        skip "This control has skipped the #{u.home} home directory for #{u.username} because it is not a local filesystem."
      end
    end
  end

  # Report on any interactive files that are less restrictive than 077.
  describe 'No interactive user initialization files with a less restrictive umask were found.' do
    subject { findings.empty? }
    it { should eq true }
  end

  # Report on any interactive users that have a umask less restrictive than 077.
  describe 'No users were found with a less restrictive umask were found.' do
    subject { umask_findings.empty? }
    it { should eq true }
  end
end
