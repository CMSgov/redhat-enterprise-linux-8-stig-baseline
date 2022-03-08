control 'SV-230280' do
  title "RHEL 8 must implement address space layout randomization (ASLR) to
protect its memory from unauthorized code execution."
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
    Verify RHEL 8 implements ASLR with the following command:

    $ sudo sysctl kernel.randomize_va_space

    kernel.randomize_va_space = 2

    If nothing is returned, verify the kernel parameter \"randomize_va_space\"
is set to \"2\" with the following command:

    $ sudo cat /proc/sys/kernel/randomize_va_space

    2

    If \"kernel.randomize_va_space\" is not set to \"2\", this is a finding.
  "
  desc 'fix', "
    Configure the operating system to implement virtual address space
randomization.

    Set the system to the required kernel parameter by adding the following
line to \"/etc/sysctl.d/*.conf\"(or modify the line to have the required value):

    kernel.randomize_va_space=2

    Issue the following command to make the changes take effect:

    $ sudo sysctl --system
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000433-GPOS-00193'
  tag gid: 'V-230280'
  tag rid: 'SV-230280r627750_rule'
  tag stig_id: 'RHEL-08-010430'
  tag fix_id: 'F-32924r567587_fix'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    describe kernel_parameter('kernel.randomize_va_space') do
      its('value') { should eq 2 }
    end
  end
end
