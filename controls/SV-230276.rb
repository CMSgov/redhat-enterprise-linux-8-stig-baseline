control 'SV-230276' do
  title "RHEL 8 must implement non-executable data to protect its memory from
unauthorized code execution."
  desc  "Some adversaries launch attacks with the intent of executing code in
non-executable regions of memory or in memory locations that are prohibited.
Security safeguards employed to protect memory include, for example, data
execution prevention and address space layout randomization. Data execution
prevention safeguards can be either hardware-enforced or software-enforced with
hardware providing the greater strength of mechanism.

    Examples of attacks are buffer overflow attacks.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the NX (no-execution) bit flag is set on the system.

    Check that the no-execution bit flag is set with the following commands:

    $ sudo dmesg | grep NX

    [ 0.000000] NX (Execute Disable) protection: active

    If \"dmesg\" does not show \"NX (Execute Disable) protection\" active,
check the cpuinfo settings with the following command:

    $ sudo less /proc/cpuinfo | grep -i flags
    flags : fpu vme de pse tsc ms nx rdtscp lm constant_tsc

    If \"flags\" does not contain the \"nx\" flag, this is a finding.
  "
  desc 'fix', "The NX bit execute protection must be enabled in the system
BIOS."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000433-GPOS-00192'
  tag gid: 'V-230276'
  tag rid: 'SV-230276r627750_rule'
  tag stig_id: 'RHEL-08-010420'
  tag fix_id: 'F-32920r567575_fix'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']

  options = {
    assignment_regex: /^\s*([^:]*?)\s*:\s*(.*?)\s*$/,
  }

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    describe.one do
      describe command('dmesg | grep NX') do
        it('stdout') { should match /.+(NX \(Execute Disable\) protection: active)/ }
      end
      describe parse_config_file('/proc/cpuinfo', options) do
        its('flags.split') { should include 'nx' }
      end
    end
  end
end
