#!/bin/bash
# Description: this script configure a smoke test environment to test agent jmx metric collection inside containers
# Authour: l.tagliamonte
# Date: 25/06/2015

SYSDIG_ACCESS_KEY="342b8432-12ee-4b75-915f-df5422e40de9"
COLLECTOR_ENDPOINT="collector-staging.sysdigcloud.com"

function tomcat_traffic(){
    while true
    do
        curl -s "http://127.0.0.1:8888/examples/jsp/jsp2/el/basic-arithmetic.jsp" >> /dev/null
        curl -s "http://127.0.0.1:8888/examples/servlets/servlet/HelloWorldExample" >> /dev/null
        sleep 1
    done
}

function activemq_traffic(){
    curl -Os https://s3.amazonaws.com/draios-testinfrastructure/jmx/activemq-queue-receiver.jar
    curl -Os https://s3.amazonaws.com/draios-testinfrastructure/jmx/activemq-sender-queue.jar
    curl -Os https://s3.amazonaws.com/draios-testinfrastructure/jmx/activemq-sender-topic.jar
    curl -Os https://s3.amazonaws.com/draios-testinfrastructure/jmx/activemq-topic-receiver.jar
    nohup java -jar activemq-sender-queue.jar &
    nohup java -jar activemq-sender-topic.jar &
    nohup java -jar activemq-queue-receiver.jar &
    nohup java -jar activemq-topic-receiver.jar &
}

function kafka_traffic(){
    sleep 20
    pip install kafka-python
    curl -Os https://raw.githubusercontent.com/mumrah/kafka-python/master/example.py
    python example.py
}

function install_agent(){
    curl -s https://s3.amazonaws.com/download.draios.com/dev/install-agent | bash -s -- -a ${SYSDIG_ACCESS_KEY} -t role:jmx-agent-container -c ${COLLECTOR_ENDPOINT}
}

function install_agent_in_container(){
    docker run -d --name sysdig-agent --privileged --net host --pid host -e ACCESS_KEY=${SYSDIG_ACCESS_KEY} -e TAGS=jmx-agent-container -e COLLECTOR=${COLLECTOR_ENDPOINT} -v /var/run/docker.sock:/host/var/run/docker.sock -v /dev:/host/dev -v /proc:/host/proc:ro -v /boot:/host/boot:ro -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro sysdig/agent
}

function configure_server(){
    yum install -y docker
    service docker start
}

function install_activemq(){
    mkdir -p /data/activemq
    mkdir -p /var/log/activemq
    docker run -d -p 61616:61616 -p 8161:8161 -p 5672:5672 -u="root" --name activemq rmohr/activemq
    docker exec activemq bash -c "rm -f /opt/activemq/conf/jmx.*"
    docker exec activemq bash -c "printf '\n'>> /opt/activemq/bin/linux-x86-64/wrapper.conf"
    docker exec activemq bash -c "echo 'wrapper.java.additional.13=-Dcom.sun.management.jmxremote.port=1616' >> /opt/activemq/bin/linux-x86-64/wrapper.conf"
    docker exec activemq bash -c "echo 'wrapper.java.additional.14=-Dcom.sun.management.jmxremote.authenticate=false' >> /opt/activemq/bin/linux-x86-64/wrapper.conf"
    docker exec activemq bash -c "echo 'wrapper.java.additional.15=-Dcom.sun.management.jmxremote.ssl=false' >> /opt/activemq/bin/linux-x86-64/wrapper.conf"
    docker restart activemq
}

function install_cassandra(){

cat <<- EOF > cassandra-test.cql
    CREATE KEYSPACE mykeyspace
    WITH REPLICATION = { 'class' : 'SimpleStrategy', 'replication_factor' : 1 };
    USE mykeyspace;
    CREATE TABLE users (user_id int PRIMARY KEY,fname text,lname text);
    INSERT INTO users (user_id,  fname, lname) VALUES (1745, 'john', 'smith');
    INSERT INTO users (user_id,  fname, lname) VALUES (1744, 'john', 'doe');
    INSERT INTO users (user_id,  fname, lname) VALUES (1746, 'john', 'smith');
    SELECT * FROM users;
EOF

    docker run --name cassandra-alone -d  -v $(pwd)/cassandra-test.cql:/cassandra-test.cql cassandra:latest
    sleep 20
    docker exec cassandra-alone bash -c "cqlsh -f /cassandra-test.cql"
}

function install_tomcat(){
cat <<- EOF > context.xml
    <Context>
    <Resource name="jdbc/TestDB" auth="Container" type="javax.sql.DataSource"
                   maxActive="100" maxIdle="30" maxWait="10000"
                   username="javauser" password="javadude" driverClassName="com.mysql.jdbc.Driver"
                   url="jdbc:mysql://localhost:3306/javatest"/>
    </Context>
EOF

    docker run -d -p 8888:8080 -v $(pwd)/context.xml:/usr/local/tomcat/conf/context.xml tomcat:7.0
}

function install_hbase(){
    docker run -p 2181:2181 -p 60010:60010 -p 60000:60000 -p 60020:60020 -p 60030:60030 -d -h hbase nerdammer/hbase
}

function install_zookeper(){
    docker run -d --name zookeeper jplock/zookeeper:3.4.6
}

function install_kafka(){
    ZK_IP=$(docker inspect --format '{{ .NetworkSettings.IPAddress }}' zookeeper)
    docker run -d --name kafka -u="root" -e "ZOOKEEPERS=$ZK_IP" -p 9092:9092 kousha/kafka
    docker exec kafka bash -c "sed -i \"s/^advertised.host.name=.*/advertised.host.name=127.0.0.1/\" /opt/kafka_2.10-0.8.2.1/config/server.properties"
    docker exec kafka bash -c "sed -i \"s/^metadata.broker.list=.*/metadata.broker.list=127.0.0.1:9092/\" /opt/kafka_2.10-0.8.2.1/config/producer.properties"
    docker restart kafka
}

#main
configure_server
install_activemq
install_cassandra
install_tomcat
install_hbase
install_zookeper
install_kafka
tomcat_traffic &
activemq_traffic &
kafka_traffic &
install_agent
#install_agent_in_container
exit 0