control 'SV-230221' do
  title 'RHEL 8 must be a vendor-supported release.'
  desc  "An operating system release is considered \"supported\" if the vendor
continues to provide security patches for the product. With an unsupported
release, it will not be possible to resolve security issues discovered in the
system software.

    Red Hat offers the Extended Update Support (EUS) ad-on to a Red Hat
Enterprise Linux subscription, for a fee, for those customers who wish to
standardize on a specific minor release for an extended period. The RHEL 8
minor releases eligible for EUS are 8.1, 8.2, 8.4, 8.6, and 8.8. Each RHEL 8
EUS stream is available for 24 months from the availability of the minor
release. RHEL 8.10 will be the final minor release overall. For more details on
the Red Hat Enterprise Linux Life Cycle  visit
https://access.redhat.com/support/policy/updates/errata.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the version of the operating system is vendor supported.

    Check the version of the operating system with the following command:

    $ sudo cat /etc/redhat-release

    Red Hat Enterprise Linux Server release 8.4 (Ootpa)

    Current End of Extended Update Support for RHEL 8.1 is 30 November 2021.

    Current End of Extended Update Support for RHEL 8.2 is 30 April 2022.

    Current End of Extended Update Support for RHEL 8.4 is 30 April 2023.

    Current End of Maintenance Support for RHEL 8.5 is 30 April 2022.

    Current End of Extended Update Support for RHEL 8.6 is 30 April 2024.

    Current End of Maintenance Support for RHEL 8.7 is 30 April 2023.

    Current End of Extended Update Support for RHEL 8.8 is 30 April 2025.

    Current End of Maintenance Support for RHEL 8.9 is 30 April 2024.

    Current End of Maintenance Support for RHEL 8.10 is 31 May 2029.

    If the release is not supported by the vendor, this is a finding.
  "
  desc  'fix', 'Upgrade to a supported version of RHEL 8.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230221'
  tag rid: 'SV-230221r743913_rule'
  tag stig_id: 'RHEL-08-010000'
  tag fix_id: 'F-32865r567410_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  release = os.release

  EOMS_DATE = case release
              when /^8\.1/
                '30 November 2021'
              when /^8\.2/
                '30 April 2022'
              when /^8\.3/
                '30 April 2021'
              when /^8\.4/
                '30 April 2023'
              when /^8\.5/
                '30 April 2022'
              when /^8\.6/
                '30 April 2024'
              when /^8\.7/
                '30 April 2023'
              when /^8\.8/
                '30 April 2025'
              when /^8\.9/
                '30 April 2024'
              when /^8\.10/
                '31 May 2029'
              end

  describe "The release \"#{release}\" must still be within the support window, ending #{EOMS_DATE}" do
    subject { Date.today <= Date.parse(EOMS_DATE) }
    it { should be true }
  end
end
