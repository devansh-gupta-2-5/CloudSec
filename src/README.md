## Necessary dependencies

```bash
sudo apt update
sudo apt install libsqlite3-dev
sudo apt install libcurl4-openssl-dev
sudo apt install jq parallel
```

Change access log and error log directories accordingly

## How to run:

```bash
make run 
```
It will start app_server, monitor and nginx

```bash
chmod +x test.sh
./test.sh 
```
This will run the test suite

```bash
./client 
```
To run the client

```bash
make stop 
```
To stop the nginx server

In case you get IP banned while testing, run 

```bash
make stop 
```

or

```bash
make clean
```

For a clean rebuild

```bash
make clean
```

