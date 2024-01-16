class SudoersUserSpecTable

  FilterTable.create
    .register_column(:users, field: :users)
    .register_column(:hosts, field: :hosts)
    .register_column(:run_as, field: :run_as)
    .register_column(:tags, field: :tags)
    .register_column(:commands, field: :commands)
    .install_filter_methods_on_resource(self, :table)

  attr_reader :table

  def initialize(userspec_lines)
        
    tags = ["NOPASSWD", "PASSWD", "NOEXEC", "EXEC", "SETENV", "NOSETENV", "LOG_INPUT", "NOLOG_INPUT", "LOG_OUTPUT", "NOLOG_OUTPUT"]

    @table = userspec_lines.map { |line|
      parsed_line = line.match(/^(?<users>\S+)\s+(?<hosts>[^=\s]+)=(\((?<run_as>.+)\))?\s*(?<tags>(#{tags.join(':|')}:)+)*\s*(?<commands>.*)$/)

      # tried just using `.named_captures` to construct the hash, but that gives hash keys that are strings, which confuses filtertable
      unless parsed_line.nil? 
        {
          users:    parsed_line['users'],
          hosts:    parsed_line['hosts'],
          run_as:   parsed_line['run_as'],
          tags:     parsed_line['tags'],
          commands: parsed_line['commands']
        }.transform_values { |v| (v.present? && v.include?(',')) ? v.split(',') : v }
      end
    }.compact
  end

  def to_s
    "Sudoers User Permissions Table"
  end
end


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

  attr_reader :lines, :settings, :sudoers_file, :table

  def initialize(sudoers_files=["/etc/sudoers"])

    # TODO - catch nonexistent files
    # TODO - figure out precendence for different sudo files; do we need to accout for that?

    @sudoers_files = sudoers_files
    sudo_configs = command("cat #{@sudoers_files.map(&:strip).join(' ')}").stdout

    # strip comment lines and blank space lines (except for the #include, just in case)
    @lines = inspec.file(@sudoers_file).content.lines.reject { |line| line.match(/^#(?!include)|^\s*$/) }.map(&:strip)

    # a sudoers file has both settings and user specifications
    # it gets easier to write parsing regexes if we split the logic for handling them
    aliases = ["Defaults","Cmnd_Alias","User_Alias","Host_Alias", "Runas_Alias"]

    settings_lines = @lines.select { |line| line.match(/^(#{aliases.join('|')})/) }
    userspec_lines = @lines.reject { |line| line.match(/^(#{aliases.join('|')})/) }

    # send the lines related to aliases or default settings to the Hashie Mash
    @settings = settings_hash(settings_lines)

    # send the rest to the FilterTable, since they are user specification lines (user-machine-command tuples)
    @table = SudoersUserSpecTable.new(userspec_lines)
  end

  def rules
    @table
  end

  private

  def settings_hash(settings_lines)
      parse_options = {
          assignment_regex: /^\s*([^=]*?)\s*\+?=\s*(.*?)\s*$/,
          multiple_values: true
      }
      sudo_config_data = inspec.parse_config(settings_lines.join("\n"), parse_options).params
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