control 'SV-230271' do
  title "RHEL 8 must require users to provide a password for privilege
escalation."
  desc  "Without reauthentication, users may access resources or perform tasks
for which they do not have authorization.

    When operating systems provide the capability to escalate a functional
capability, it is critical the user reauthenticate.


  "
  desc  'rationale', ''
  desc  'check', "
    Verify that \"/etc/sudoers\" has no occurrences of \"NOPASSWD\".

    Check that the \"/etc/sudoers\" file has no occurrences of \"NOPASSWD\" by
running the following command:

    $ sudo grep -i nopasswd /etc/sudoers /etc/sudoers.d/*

    %admin ALL=(ALL) NOPASSWD: ALL

    If any occurrences of \"NOPASSWD\" are returned from the command and have
not been documented with the ISSO as an organizationally defined administrative
group utilizing MFA, this is a finding.
  "
  desc  'fix', "Remove any occurrence of \"NOPASSWD\" found in \"/etc/sudoers\"
file or files in the \"/etc/sudoers.d\" directory."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag satisfies: %w(SRG-OS-000373-GPOS-00156 SRG-OS-000373-GPOS-00157
                    SRG-OS-000373-GPOS-00158)
  tag gid: 'V-230271'
  tag rid: 'SV-230271r627750_rule'
  tag stig_id: 'RHEL-08-010380'
  tag fix_id: 'F-32915r567560_fix'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']

  if virtualization.system.eql?('docker') && !command("sudo").exist?
    impact 0.0
    describe "Control not applicable within a container & sudo doesn't exist" do
      skip "Control not applicable within a container & sudo doesn't exist"
    end
  else
    processed = []
    to_process = ['/etc/sudoers', '/etc/sudoers.d']

    until to_process.empty?
      in_process = to_process.pop
      next if processed.include? in_process
      processed.push in_process

      if file(in_process).directory?
        to_process.concat(
          command("find #{in_process} -maxdepth 1 -mindepth 1")
            .stdout.strip.split("\n")
            .select { |f| file(f).file? }
        )
      elsif file(in_process).file?
        to_process.concat(
          command("grep -E '#include\\s+' #{in_process} | sed 's/.*#include[[:space:]]*//g'")
            .stdout.strip.split("\n")
            .map { |f| f.start_with?('/') ? f : File.join(File.dirname(in_process), f) }
            .select { |f| file(f).exist? }
        )
        to_process.concat(
          command("grep -E '#includedir\\s+' #{in_process} | sed 's/.*#includedir[[:space:]]*//g'")
            .stdout.strip.split("\n")
            .map { |f| f.start_with?('/') ? f : File.join(File.dirname(in_process), f) }
            .select { |f| file(f).exist? }
        )
      end
    end

    sudoers = processed.select { |f| file(f).file? }

    sudoers.each do |sudoer|
      sudo_content = file(sudoer).content.strip.split("\n")
      nopasswd_lines = sudo_content.select { |l| l.match?(/^[^#].*NOPASSWD/) }
      describe "#{sudoer} rules containing NOPASSWD" do
        subject { nopasswd_lines }
        it { should be_empty }
      end
    end
  end
end
