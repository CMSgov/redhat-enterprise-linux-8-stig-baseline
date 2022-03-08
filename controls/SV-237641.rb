control 'SV-237641' do
  title 'RHEL 8 must restrict privilege elevation to authorized personnel.'
  desc  "The sudo command allows a user to execute programs with elevated
(administrator) privileges. It prompts the user for their password and confirms
your request to execute a command by checking a file, called sudoers. If the
\"sudoers\" file is not configured correctly, any user defined on the system
can initiate privileged actions on the target system."
  desc  'rationale', ''
  desc  'check', "
    Verify the \"sudoers\" file restricts sudo access to authorized personnel.
    $ sudo grep -iw 'ALL' /etc/sudoers /etc/sudoers.d/*

    If the either of the following entries are returned, this is a finding:
    ALL     ALL=(ALL) ALL
    ALL     ALL=(ALL:ALL) ALL
  "
  desc 'fix', "
    Remove the following entries from the sudoers file:
    ALL     ALL=(ALL) ALL
    ALL     ALL=(ALL:ALL) ALL
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-237641'
  tag rid: 'SV-237641r646893_rule'
  tag stig_id: 'RHEL-08-010382'
  tag fix_id: 'F-40823r646892_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  sudoers_files = bash('ls -d /etc/sudoers.d/*').stdout.strip.split.append('/etc/sudoers')

  if virtualization.system.eql?('docker') && !command("sudo").exist?
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    sudoers_files.each do |file|
      describe file(file) do
        its('content') { should_not match /^ALL[\s]*ALL=\(ALL\)\sALL/ }
        its('content') { should_not match /^ALL[\s]*ALL=\(ALL:ALL\)\sALL/ }
      end
    end
  end
end
