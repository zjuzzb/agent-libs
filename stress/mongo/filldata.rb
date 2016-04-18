require 'faker'
require 'mongo'

include Mongo

client = MongoClient.new(ENV['MONGODB'], 27017)
db = client["test"]
collection = db["customers"]

300000.times do
	collection.insert({
			:first_name => Faker::Name.first_name,
			:last_name => Faker::Name.last_name,
			:city => Faker::Address.city,
			:country_code => Faker::Address.country_code,
			:orders_count => Random.rand(10)+1
		})
end
