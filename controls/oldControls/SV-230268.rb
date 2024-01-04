control 'SV-230268' do
  title 'RHEL 8 must enable kernel parameters to enforce discretionary access control on hardlinks.'
  desc 'Discretionary Access Control (DAC) is based on the notion that individual users are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. DAC allows the owner to determine who will have access to objects they control. An example of DAC includes user-controlled file permissions.

    When discretionary access control policies are implemented, subjects are not constrained with regard to what actions they can take with information for which they have already been granted access. Thus, subjects that have been granted access to information are not prevented from passing (i.e., the subjects have the discretion to pass) the information to other subjects or objects. A subject that is constrained in its operation by Mandatory Access Control policies is still able to operate under the less rigorous constraints of this requirement. Thus, while Mandatory Access Control imposes constraints preventing a subject from passing information to another subject operating at a different sensitivity level, this requirement permits the subject to pass the information to any subject at the same sensitivity level. The policy is bounded by the information system boundary. Once the information is passed outside the control of the information system, additional means may be required to ensure the constraints remain in effect. While the older, more traditional definitions of discretionary access control require identity-based access control, that limitation is not required for this use of discretionary access control.

    By enabling the fs.protected_hardlinks kernel parameter, users can no longer create soft or hard links to files they do not own. Disallowing such hardlinks mitigate vulnerabilities based on insecure file system accessed by privileged programs, avoiding an exploitation vector exploiting unsafe use of open() or creat().

    The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.

    /etc/sysctl.d/*.conf
    /run/sysctl.d/*.conf
    /usr/local/lib/sysctl.d/*.conf
    /usr/lib/sysctl.d/*.conf
    /lib/sysctl.d/*.conf
    /etc/sysctl.conf'
  desc 'check', 'Verify the operating system is configured to enable DAC on hardlinks with the following commands:

  Check the status of the fs.protected_hardlinks kernel parameter.

  $ sudo sysctl fs.protected_hardlinks

  fs.protected_hardlinks = 1

  If "fs.protected_hardlinks" is not set to "1" or is missing, this is a finding.

  Check that the configuration files are present to enable this kernel parameter.

  $ sudo grep -r fs.protected_hardlinks /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

  /etc/sysctl.d/99-sysctl.conf:fs.protected_hardlinks = 1

  If "fs.protected_hardlinks" is not set to "1", is missing or commented out, this is a finding.

  If conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure the operating system to enable DAC on hardlinks.

  Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

  fs.protected_hardlinks = 1

  Remove any configurations that conflict with the above from the following locations:
  /run/sysctl.d/*.conf
  /usr/local/lib/sysctl.d/*.conf
  /usr/lib/sysctl.d/*.conf
  /lib/sysctl.d/*.conf
  /etc/sysctl.conf
  /etc/sysctl.d/*.conf

  Load settings from all system configuration files with the following command:

  $ sudo sysctl --system'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000312-GPOS-00122'
  tag satisfies: ['SRG-OS-000312-GPOS-00122', 'SRG-OS-000312-GPOS-00123', 'SRG-OS-000312-GPOS-00124', 'SRG-OS-000324-GPOS-00125']
  tag gid: 'V-230268'
  tag rid: 'SV-230268r858754_rule'
  tag stig_id: 'RHEL-08-010374'
  tag fix_id: 'F-32912r858753_fix'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']

  # Define the kernel parameter to be checked
  parameter = 'fs.protected_hardlinks'
  action = 'enforce discretionary access control on hardlinks'

  # Get the current value of the kernel parameter
  current_value = kernel_parameter(parameter)

  # Check if the system is a Docker container
  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  else
    # Check if IPv4 packet forwarding is disabled
    describe action.to_s do
      it 'is disabled in sysctl -a' do
        expect(current_value.value).to cmp 0
        expect(current_value.value).not_to be_nil
      end
    end

    # Get the list of sysctl configuration files
    sysctl_config_files = input('sysctl_conf_files').map(&:strip).join(' ')

    # Search for the kernel parameter in the configuration files
    search_results = command("grep -r #{parameter} #{sysctl_config_files} {} \;").stdout.split("\n")

    # Parse the search results into a hash
    config_values = search_results.each_with_object({}) do |item, results|
      file, setting = item.split(':')
      results[file] ||= []
      results[file] << setting.split('=').last
    end

    # Check the configuration files
    describe 'Configuration files' do
      if search_results.empty?
        it "do not have `#{parameter}` disabled directly" do
          expect(config_values).not_to be_empty, "Add the line `#{parameter}=0` to a file in the `/etc/sysctl.d/` directory"
        end
      else
        describe "for #{action}" do
          it 'have a single unique entry' do
            expect(config_values.values.flatten.count).to eq(1), "Expected one unique configuration, but got #{config_values}"
          end

          it "do not have more then one #{action} value" do
            expect(config_values.values.flatten.all? { |v| v == '0' }).to be true
          end
        end
      end
    end
  end
end
