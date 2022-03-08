control 'SV-230504' do
  title "A RHEL 8 firewall must employ a deny-all, allow-by-exception policy
for allowing connections to other systems."
  desc  "Failure to restrict network connectivity only to authorized systems
permits inbound connections from malicious systems. It also permits outbound
connections that may facilitate exfiltration of DoD data.

    RHEL 8 incorporates the \"firewalld\" daemon, which allows for many
different configurations. One of these configurations is zones. Zones can be
utilized to a deny-all, allow-by-exception approach. The default \"drop\" zone
will drop all incoming network packets unless it is explicitly allowed by the
configuration file or is related to an outgoing network connection.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify \"firewalld\" is configured to employ a deny-all, allow-by-exception
policy for allowing connections to other systems with the following commands:

    $ sudo  firewall-cmd --state

    running

    $ sudo firewall-cmd --get-active-zones

    [custom]
       interfaces: ens33

    $ sudo firewall-cmd --info-zone=[custom] | grep target

       target: DROP

    If no zones are active on the RHEL 8 interfaces or if the target is set to
a different option other than \"DROP\", this is a finding.
  "
  desc 'fix', "
    Configure the \"firewalld\" daemon to employ a deny-all, allow-by-exception
with the following commands:

    $ sudo firewall-cmd --permanent --new-zone=[custom]

    $ sudo cp /usr/lib/firewalld/zones/drop.xml
/etc/firewalld/zones/[custom].xml

    This will provide a clean configuration file to work with that employs a
deny-all approach. Next, add the exceptions that are required for mission
functionality.

    $ sudo firewall-cmd --set-default-zone=[custom]

    Note: This is a runtime and permanent change.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000297-GPOS-00115'
  tag gid: 'V-230504'
  tag rid: 'SV-230504r627750_rule'
  tag stig_id: 'RHEL-08-040090'
  tag fix_id: 'F-33148r568259_fix'
  tag cci: ['CCI-002314']
  tag legacy: []
  tag nist: ['AC-17 (1)']

  if virtualization.system.eql?('docker')
    impact 0.0
    describe "Control not applicable within a container" do
      skip "Control not applicable within a container"
    end
  else
    describe firewalld do
      it { should be_running }
    end
  
    describe firewalld.zone do
      it { should_not be_empty }
    end
  
    firewalld.zone.each do |zone|
      describe "Firewall zone \'#{zone}\' target" do
        subject { firewalld.zone(zone).target }
        it { should cmp 'DROP' }
      end
    end
  end
end
