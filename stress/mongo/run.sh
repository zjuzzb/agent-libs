# make sure the mongo container is stopped and removed
docker kill $(docker ps -a | grep mongotest | awk '{print $1 }')
docker rm $(docker ps -a | grep mongotest | awk '{print $1 }')

# run the mongo container
docker run --name mongotest -d mongo

# populate the data
MIP=`docker inspect --format='{{ .NetworkSettings.IPAddress }}' mongotest`
echo "pushing data..."
MONGODB=$MIP ruby filldata.rb

# start the clients
echo "starting clients..."
MONGODB=$MIP ruby query_agg.rb > /dev/null &
MONGODB=$MIP ruby query_mr.rb > /dev/null &
echo "done. Press a key to finish"

# Wait for key and cleanup
read -p "Press any key to continue... " -n1 -s
killall -9 ruby
docker kill $(docker ps -a | grep mongotest | awk '{print $1 }')
docker rm $(docker ps -a | grep mongotest | awk '{print $1 }')
