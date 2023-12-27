require 'csv'

input_file = 'control-status.csv'
output_file = 'control-status-quoted.csv'

CSV.open(output_file, 'w') do |csv|
  CSV.foreach(input_file) do |row|
    csv << row.map { |column| column.strip.to_s }
  end
end
