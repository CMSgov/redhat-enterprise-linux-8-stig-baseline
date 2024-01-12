


class Sudoers < Inspec.resource(1)

    name "sudoers"
    supports platform: "unix"
    desc "Parse sudoers files"

    example "
      # Find users with NOPASSWD set:  
      describe sudoers.users.where do
        its('rules') { should match_pam_rule('password sufficient pam_unix.so sha512') }
      end
    "

    attr_reader :lines, :settings, :sudoers_file

    def initialize(sudoers_file="/etc/sudoers")
        @sudoers_file = sudoers_file
        @lines = inspec.file(@sudoers_file).content.lines

        # send some lines to the Hashie Mash
        @settings = settings_hash(@lines.select { |line| line.match(/^(Defaults|Cmnd_Alias|User_Alias|Host_Alias)/) } )

        # send the rest to the FilterTable as user-machine-command tuple
    end

    private

    def settings_hash(lines)
        puts "Settings Hash: lines =\n#{lines}"
        # sudoers_config_files = input('sudoers_config_files').map(&:strip).join(' ')
        # sudo_configs = command("cat #{sudoers_config_files}").stdout
        parse_options = {
            assignment_regex: /^\s*([^=]*?)\s*\+?=\s*(.*?)\s*$/,
            multiple_values: true
        }
        sudo_config_data = inspec.parse_config(lines.join("\n"), parse_options).params
        sudo_config_hash = Hashie::Mash.new
        sudo_config_data.each do |k, v|
            if k.start_with?('Defaults')
                key_parts = k.split('   ', 2) # split by three spaces
                sudo_config_hash.Defaults ||= Hashie::Mash.new
                sudo_config_hash.Defaults[key_parts[1].strip] = v.map { |x| x.delete("\"") }.map(&:split).flatten
            else
                key_parts = k.split("\t") # split by tab character
                sudo_config_hash[key_parts[0]] ||= Hashie::Mash.new
                sudo_config_hash[key_parts[0]][key_parts[1]] = v
            end
        end
        sudo_config_hash
    end
end