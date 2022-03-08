control 'SV-230286' do
  title "The RHEL 8 SSH public host key files must have mode 0644 or less
permissive."
  desc  "If a public host key file is modified by an unauthorized user, the SSH
service may be compromised."
  desc  'rationale', ''
  desc  'check', "
    Verify the SSH public host key files have mode \"0644\" or less permissive
with the following command:

    $ sudo ls -l /etc/ssh/*.pub

    -rw-r--r-- 1 root root 618 Nov 28 06:43 ssh_host_dsa_key.pub
    -rw-r--r-- 1 root root 347 Nov 28 06:43 ssh_host_key.pub
    -rw-r--r-- 1 root root 238 Nov 28 06:43 ssh_host_rsa_key.pub

    If any key.pub file has a mode more permissive than \"0644\", this is a
finding.

    Note: SSH public key files may be found in other directories on the system
depending on the installation.
  "
  desc 'fix', "
    Change the mode of public host key files under \"/etc/ssh\" to \"0644\"
with the following command:

    $ sudo chmod 0644 /etc/ssh/*key.pub

    The SSH daemon must be restarted for the changes to take effect. To restart
the SSH daemon, run the following command:

    $ sudo systemctl restart sshd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230286'
  tag rid: 'SV-230286r627750_rule'
  tag stig_id: 'RHEL-08-010480'
  tag fix_id: 'F-32930r567605_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if virtualization.system.eql?('docker') && !directory('/etc/ssh').exist?
    impact 0.0
    describe "Control not applicable - SSH is not installed within containerized RHEL" do
      skip "Control not applicable - SSH is not installed within containerized RHEL"
    end
  else
    pub_files = command("find /etc/ssh -xdev -name '*.pub' -perm /133").stdout.split("\n")
    if !pub_files.nil? && !pub_files.empty?
      pub_files.each do |pubfile|
        describe file(pubfile) do
          it { should_not be_more_permissive_than('0644') }
        end
      end
    else
      describe 'No files have a more permissive mode.' do
        subject { pub_files.nil? || pub_files.empty? }
        it { should eq true }
      end
    end
  end
end
