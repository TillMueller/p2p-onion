tmux \
	new-session 'watch -n 1 "netstat -tuln | grep :655"' \; \
	split-window 'go run main.go -c testing_setup/peer0/config.ini' \; \
	split-window 'go run main.go -c testing_setup/peer1/config.ini' \;
