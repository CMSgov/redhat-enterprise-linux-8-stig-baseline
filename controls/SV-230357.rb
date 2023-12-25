# frozen_string_literal: true

# TODO: Add this to the course content as a teaching example

control 'SV-230357' do
  title "RHEL 8 must enforce password complexity by requiring that at least one
uppercase character be used."
  desc 'Use of a complex password helps to increase the time and resources
required to compromise the password. Password complexity, or strength, is a
measure of the effectiveness of a password in resisting attempts at guessing
and brute-force attacks.

    Password complexity is one factor of several that determines how long it
takes to crack a password. The more complex the password, the greater the
number of possible combinations that need to be tested before the password is
compromised.

    RHEL 8 utilizes pwquality as a mechanism to enforce password complexity.
Note that in order to require uppercase characters, without degrading the
"minlen" value, the credit value must be expressed as a negative number in
"/etc/security/pwquality.conf".'

  desc 'check', 'Verify the value for "ucredit" with the following command:

$ sudo grep -r ucredit /etc/security/pwquality.conf*

/etc/security/pwquality.conf:ucredit = -1

If the value of "ucredit" is a positive number or is commented out, this is a finding.

If conflicting results are returned, this is a finding.'

  desc 'fix', 'Configure the operating system to enforce password complexity by requiring that at least one uppercase character be used by setting the "ucredit" option.

Add the following line to /etc/security/pwquality.conf (or modify the line to have the required value):

ucredit = -1

Remove any configurations that conflict with the above value.'

  impact 0.5

  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag gid: 'V-230357'
  tag rid: 'SV-230357r858771_rule'
  tag stig_id: 'RHEL-08-020110'
  tag fix_id: 'F-33001r858770_fix'
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']

  describe 'pwquality.conf:' do
    let(:config) { parse_config_file('/etc/security/pwquality.conf', multiple_values: true) }
    let(:setting) { 'ucredit' }
    let(:value) { Array(config.params[setting]) }

    it 'has `ucredit` set' do
      expect(value).not_to be_empty, 'ucredit is not set in pwquality.conf'
    end

    it 'only sets `ucredit` once' do
      expect(value.length).to eq(1), 'ucredit is commented or set more than once in pwquality.conf'
    end

    it 'does not set `ucredit` to a positive value' do
      expect(value.first.to_i).to be.negative?, 'ucredit is not set to a negative value in pwquality.conf'
    end
  end
end

## More Elegant but complicated Approach
#
#   describe 'pwquality.conf:' do
#     let(:config) { parse_config_file('/etc/security/pwquality.conf', multiple_values: true) }
#     let(:setting) { 'ucredit' }
#     let(:values) { Array(config.params[setting]) }
#     let(:count) { values.length }

#     it 'only sets `ucredit` once' do
#       expect(count).to eq(1), 'ucredit is not set or set multiple times in pwquality.conf'
#     end

#     context 'when `ucredit` is set,' do
#       before { raise 'ucredit is not configured or commented out in pwquality.conf' if count.zero? }

#       it 'does not set `ucredit` to a positive value' do
#         expect(values.first.to_i).to be < 0, 'ucredit is not set to a negative value in pwquality.conf'
#       end
#     end
#   end
# end

# - The Array() function is used to ensure that values is always an array.
#   If config.params[setting] is nil, Array(nil) will return an empty array.
#
# - If config.params[setting] is a single value, Array(value) will return an array with
#   that value as its only element.
#
# - The count variable is set to the length of the values array. If ucredit is not set,
#   values will be an empty array and count will be 0.
#
# - The values.first.to_i in the last it block is used to convert the first value of
#   ucredit to an integer before comparing it to 0. If ucredit is not set, values.first
#   will be nil, and nil.to_i will return 0, causing the test to fail.

# - The & operator is used to safely call the length and first methods on value.
#   If value is nil, &.length and &.first will also return nil, and the tests will
#   fail with the message 'ucredit is not set in pwquality.conf'.
#
# - The to_i method is called on value&.first to convert the first value of ucredit
#   to an integer before comparing it to 0. If ucredit is not set, value&.first will
#   be nil, and nil.to_i will return 0, causing the test to fail.
#
