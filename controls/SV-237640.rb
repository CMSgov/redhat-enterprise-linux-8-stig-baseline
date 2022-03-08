control 'SV-237640' do
  title 'The krb5-server package must not be installed on RHEL 8.'
  desc  "Unapproved mechanisms that are used for authentication to the
cryptographic module are not verified and therefore cannot be relied upon to
provide confidentiality or integrity, and DoD data may be compromised.

    RHEL 8 systems utilizing encryption are required to use FIPS-compliant
mechanisms for authenticating to cryptographic modules.

    Currently, Kerberos does not utilize FIPS 140-2 cryptography.

    FIPS 140-2 is the current standard for validating that mechanisms used to
access cryptographic modules utilize authentication that meets DoD
requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a
general-purpose computing system.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the krb5-server package has not been installed on the system with
the following commands:

    If the system is a workstation or is utilizing
krb5-server-1.17-18.el8.x86_64 or newer, this is Not Applicable

    $ sudo yum list installed krb5-server

    krb5-server.x86_64 1.17-9.el8 repository

    If the krb5-server package is installed and is not documented with the
Information System Security Officer (ISSO) as an operational requirement, this
is a finding.
  "
  desc 'fix', "
    Document the krb5-server package with the ISSO as an operational
requirement or remove it from the system with the following command:

    $ sudo yum remove krb5-server
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag gid: 'V-237640'
  tag rid: 'SV-237640r646890_rule'
  tag stig_id: 'RHEL-08-010163'
  tag fix_id: 'F-40822r646889_fix'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']

  describe.one do
    describe package('krb5-server') do
      it { should_not be_installed }
    end

    describe package('krb5-server') do
      its('version') { should cmp >= '1.17-9.el8' }
    end
  end
end
