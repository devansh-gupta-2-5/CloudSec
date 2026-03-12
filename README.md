sudo apt update
sudo apt install libsqlite3-dev
sudo apt install libcurl4-openssl-dev
sudo apt install jq parallel

Necessary dependencies

Change access log and error log directories accordingly

How to run:
make run 
It will start app_server, monitor and nginx

chmod +x test.sh
./test.sh 
This will run the test suite

./client 
To run the client

make stop 
To stop the nginx server

make clean
For a clean rebuild


