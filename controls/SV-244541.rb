control 'SV-244541' do
  title 'RHEL 8 must not allow blank or null passwords in the password-auth
file.'
  desc 'If an account has an empty password, anyone could log on and run
commands with the privileges of that account. Accounts with empty passwords
should never be used in operational environments.'
  desc 'check', 'To verify that null passwords cannot be used, run the following command:

$ sudo grep -i nullok /etc/pam.d/password-auth

If output is produced, this is a finding.'
  desc 'fix', 'Remove any instances of the "nullok" option in the
"/etc/pam.d/password-auth" file to prevent logons with empty passwords.

    Note: Manual changes to the listed file may be overwritten by the
"authselect" program.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-244541'
  tag rid: 'SV-244541r743872_rule'
  tag stig_id: 'RHEL-08-020332'
  tag fix_id: 'F-47773r743871_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  pam_auth_files = input('pam_auth_files')
  file_list = pam_auth_files.values.join(' ')
  bad_entries = command("grep -i nullok #{file_list}").stdout.lines.collect(&:squish)

  describe 'The system is configureed' do
    subject { command("grep -i nullok #{file_list}") }
    it 'to not allow null passwords' do
      expect(subject.stdout.strip).to be_empty, "The system is configured to allow null passwords. Please remove any instances of the `nullok` option from: \n\t- #{bad_entries.join("\n\t- ")}"
    end
  end
end
