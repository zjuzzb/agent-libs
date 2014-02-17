 for i in `seq 17642 17692`;
        do
			python tcp_server_ex.py $i &
			python tcp_client_ex.py $i &
        done   
