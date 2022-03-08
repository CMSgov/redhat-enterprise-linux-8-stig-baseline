control 'SV-230287' do
  title "The RHEL 8 SSH private host key files must have mode 0600 or less
permissive."
  desc  "If an unauthorized user obtains the private SSH host key file, the
host could be impersonated."
  desc  'rationale', ''
  desc  'check', "
    Verify the SSH private host key files have mode \"0600\" or less permissive
with the following command:

    $ sudo ls -l /etc/ssh/ssh_host*key

    -rw------- 1 root ssh_keys 668 Nov 28 06:43 ssh_host_dsa_key
    -rw------- 1 root ssh_keys 582 Nov 28 06:43 ssh_host_key
    -rw------- 1 root ssh_keys 887 Nov 28 06:43 ssh_host_rsa_key

    If any private host key file has a mode more permissive than \"0600\", this
is a finding.
  "
  desc  'fix', "
    Configure the mode of SSH private host key files under \"/etc/ssh\" to
\"0600\" with the following command:

    $ sudo chmod 0600 /etc/ssh/ssh_host*key

    The SSH daemon must be restarted for the changes to take effect. To restart
the SSH daemon, run the following command:

    $ sudo systemctl restart sshd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230287'
  tag rid: 'SV-230287r743951_rule'
  tag stig_id: 'RHEL-08-010490'
  tag fix_id: 'F-32931r743950_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if virtualization.system.eql?('docker') && !directory('/etc/ssh').exist?
    impact 0.0
    describe "Control not applicable - SSH is not installed within containerized RHEL" do
      skip "Control not applicable - SSH is not installed within containerized RHEL"
    end
  else
    key_files = command("find /etc/ssh -xdev -name '*ssh_host*key'").stdout.split("\n")
    if !key_files.nil? && !key_files.empty?
      key_files.each do |keyfile|
        describe file(keyfile) do
          it { should_not be_more_permissive_than('0600') }
        end
      end
    else
      describe 'No files have a more permissive mode.' do
        subject { key_files.nil? || key_files.empty? }
        it { should eq true }
      end
    end
  end
end
