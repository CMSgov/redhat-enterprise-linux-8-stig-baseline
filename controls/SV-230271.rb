control 'SV-230271' do
  title 'RHEL 8 must require users to provide a password for privilege
escalation.'
  desc 'Without reauthentication, users may access resources or perform tasks
for which they do not have authorization.

    When operating systems provide the capability to escalate a functional
capability, it is critical the user reauthenticate.'
  desc 'check', 'Verify that "/etc/sudoers" has no occurrences of "NOPASSWD".

    Check that the "/etc/sudoers" file has no occurrences of "NOPASSWD" by
running the following command:

    $ sudo grep -i nopasswd /etc/sudoers /etc/sudoers.d/*

    %admin ALL=(ALL) NOPASSWD: ALL

    If any occurrences of "NOPASSWD" are returned from the command and have
not been documented with the ISSO as an organizationally defined administrative
group utilizing MFA, this is a finding.'
  desc 'fix', 'Remove any occurrence of "NOPASSWD" found in "/etc/sudoers"
file or files in the "/etc/sudoers.d" directory.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00158']
  tag gid: 'V-230271'
  tag rid: 'SV-230271r854026_rule'
  tag stig_id: 'RHEL-08-010380'
  tag fix_id: 'F-32915r854025_fix'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
  tag 'host', 'container-conditional'

  only_if('Control not applicable within a container without sudo installed', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !command('sudo').exist?)
  }

  # TODO: figure out why this .where throws an exception if we don't explicitly filter out nils via 'tags.nil?'
  # ergo shouldn't the filtertable be handling that kind of nil-checking for us?
  failing_results = sudoers(input('sudoers_config_files').join(' ')).rules.where { tags.nil? && (tags || '').include?('NOPASSWD') }

  failing_results = failing_results.where { !input('passwordless_admins').include?(users) } if input('passwordless_admins').nil?

  describe 'Sudoers' do
    it 'should not include any (non-exempt) users with NOPASSWD set' do
      expect(failing_results).to be_empty, "NOPASSWD settings found for users:\n\t- #{failing_results.users.join("\n\t- ")}"
    end
  end
end
