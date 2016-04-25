require 'mongo'
include Mongo

$stdout.sync = true

client = MongoClient.new(ENV['MONGODB'], 27017)
db = client["test"]
collection = db["customers"]

loop do
	print ">:t:map-reduce::\n" # Mark the beginning of the query

	collection.map_reduce("function() { emit(this.country_code, this.orders_count) }",
	          "function(key,values) { return Array.sum(values) }",  { :out => { :inline => true }, :raw => true});

	print "<:t:map-reduce::\n" # Mark the end of the query
end
