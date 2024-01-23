control 'SV-230301' do
  title 'RHEL 8 must prevent special devices on non-root local partitions.'
  desc 'The "nodev" mount option causes the system to not interpret
character or block special devices. Executing character or block special
devices from untrusted file systems increases the opportunity for unprivileged
users to attain unauthorized administrative access.  The only legitimate
location for device files is the /dev directory located on the root partition.'
  desc 'check', %q(Verify all non-root local partitions are mounted with the "nodev" option
with the following command:

    $ sudo mount | grep '^/dev\S* on /\S' | grep --invert-match 'nodev'

    If any output is produced, this is a finding.)
  desc 'fix', 'Configure the "/etc/fstab" to use the "nodev" option on all
non-root local partitions.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230301'
  tag rid: 'SV-230301r627750_rule'
  tag stig_id: 'RHEL-08-010580'
  tag fix_id: 'F-32945r567650_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  # TODO: figure out how mount works enough to make this test readable

  only_if('This control is does not apply to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  option = 'nodev'

  mount_stdout = command("mount").stdout.lines
  failing_mount_points = mount_stdout.reject { |mp| mp.match(/^[^\/dev\S*]\s*.*\(.*#{option}.*\)/) }

  # failing_mount_points = command("mount \| grep '^/dev\\S* on /\\S' \| grep --invert-match '#{option}'").stdout.split

  describe "All mounted devices outside of '/dev' directory" do
    it "should be mounted with the '#{option}' option" do
      expect(failing_mount_points).to be_empty, "Failing devices:\n\t- #{failing_mount_points.join("\n\t- ")}"
    end
  end
end
