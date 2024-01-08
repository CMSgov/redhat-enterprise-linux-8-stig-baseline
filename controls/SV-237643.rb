control 'SV-237643' do
  title 'RHEL 8 must require re-authentication when using the "sudo" command.'
  desc %q(Without re-authentication, users may access resources or perform tasks
for which they do not have authorization.

    When operating systems provide the capability to escalate a functional
capability, it is critical the organization requires the user to
re-authenticate when using the "sudo" command.

    If the value is set to an integer less than 0, the user's time stamp will
not expire and the user will not have to re-authenticate for privileged actions
until the user's session is terminated.)
  desc 'check', %q(Verify the operating system requires re-authentication when using the "sudo" command to elevate privileges.

$ sudo grep -ir 'timestamp_timeout' /etc/sudoers /etc/sudoers.d
/etc/sudoers:Defaults timestamp_timeout=0

If conflicting results are returned, this is a finding.

If "timestamp_timeout" is set to a negative number, is commented out, or no results are returned, this is a finding.)
  desc 'fix', 'Configure the "sudo" command to require re-authentication.
Edit the /etc/sudoers file:
$ sudo visudo

Add or modify the following line:
Defaults timestamp_timeout=[value]
Note: The "[value]" must be a number that is greater than or equal to "0".

Remove any duplicate or conflicting lines from /etc/sudoers and /etc/sudoers.d/ files.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag gid: 'V-237643'
  tag rid: 'SV-237643r861088_rule'
  tag stig_id: 'RHEL-08-010384'
  tag fix_id: 'F-40825r858763_fix'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
  tag 'host', 'container-conditional'

  sudoers_config_files = input('sudoers_config_files').map(&:strip).join(' ')
  sudo_configs = command("cat #{sudoers_config_files}").stdout

  sudo_config_data = parse_config(sudo_configs).params

  setting = 'timestamp_timeout'
  value = 0

  sudo_config_hash = Hashie::Mash.new
  sudo_config_data.each do |k, v|
    if k.start_with?('Defaults')
      key_parts = k.split('   ', 2) # split by three spaces
      sudo_config_hash.Defaults ||= Hashie::Mash.new
      sudo_config_hash.Defaults[key_parts[1].strip] = v
    else
      key_parts = k.split("\t") # split by tab character
      sudo_config_hash[key_parts[0]] ||= Hashie::Mash.new
      sudo_config_hash[key_parts[0]][key_parts[1]] = v
    end
  end

  impact 0.0 if virtualization.system.eql?('docker') && !command('sudo').exist?

  describe 'The Sudo Configuration' do
    if virtualization.system.eql?('docker') && !command('sudo').exist?
      it 'This requirement is Not Applicable since `sudo` not installed in the container.' do
        skip 'This requirement is Not Applicable since `sudo` not installed in the container.'
      end
    else
      it 'has a configured non-negative Default timestamp_timeout value' do
        expect(sudo_config_hash.Defaults[setting]).to be >= 0, "The Default #{setting} setting is not present or incorrectly configured. Please ensure #{setting} present and is not negative."
      end
      it 'has the correct Default timestamp_timeout setting' do
        expect(sudo_config_hash.Defaults[setting.to_s]).to eq(0), "The Default #{setting} setting is not present or incorrectly configured. Please ensure #{setting} is set to #{value}."
      end
    end
  end
end
