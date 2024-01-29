control 'SV-230313' do
  title 'RHEL 8 must disable core dumps for all users.'
  desc 'It is detrimental for operating systems to provide, or install by
default, functionality exceeding requirements or mission objectives. These
unnecessary capabilities or services are often overlooked and therefore may
remain unsecured. They increase the risk to the platform by providing
additional attack vectors.

    A core dump includes a memory image taken at the time the operating system
terminates an application. The memory image could contain sensitive data and is
generally useful only for developers trying to debug problems.'
  desc 'check', %q(Verify the operating system disables core dumps for all users by issuing
the following command:

    $ sudo grep -r -s '^[^#].*core' /etc/security/limits.conf
/etc/security/limits.d/*.conf

    * hard core 0

    This can be set as a global domain (with the * wildcard) but may be set
differently for multiple domains.

    If the "core" item is missing, commented out, or the value is anything
other than "0" and the need for core dumps is not documented with the
Information System Security Officer (ISSO) as an operational requirement for
all domains that have the "core" item assigned, this is a finding.)
  desc 'fix', 'Configure the operating system to disable core dumps for all users.

    Add the following line to the top of the /etc/security/limits.conf or in a
".conf" file defined in /etc/security/limits.d/:

    * hard core 0'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230313'
  tag rid: 'SV-230313r627750_rule'
  tag stig_id: 'RHEL-08-010673'
  tag fix_id: 'F-32957r619861_fix'
  tag cci: ['CCI-000366']
  tag legacy: []
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  caveat = input('core_dump_permitted')

  if caveat
    describe 'Manual Review' do
      skip 'Inputs indicate this capability is an operational requirement of this system; manually review system documentation and confirm this with the ISSO'
    end
  else

    setting = 'core'
    expected_value = 0

    limits_files = command('ls /etc/security/limits.d/*.conf').stdout.strip.split
    limits_files.append('/etc/security/limits.conf')

    # make sure that at least one limits.conf file has the correct setting
    globally_set = limits_files.any? { |lf| limits_conf(lf).read_params['*'].present? && limits_conf(lf).read_params['*'].include?(['hard', setting.to_s, expected_value.to_s]) }

    # make sure that no limits.conf file has a value that contradicts the global set
    failing_files = limits_files.select { |lf|
      limits_conf(lf).read_params.values.flatten(1).any? { |l|
        l[1].eql?(setting) && !l[2].to_i.eql?(expected_value)
      }
    }
    describe 'Limits files' do
      it 'should disallow core dumps by default' do
        expect(globally_set).to eq(true), "No correct global ('*') setting found"
      end
      it 'should not have any conflicting settings' do
        expect(failing_files).to be_empty, "Files with incorrect '#{setting}' settings:\n\t- #{failing_files.join("\n\t- ")}"
      end
    end
  end
end
