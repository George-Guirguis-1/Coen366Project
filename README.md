# Coen366Project

## Steps to follow to run the servers

1. On the server computer, run:
   ```
   python server.py
   ```
2. Note the IP address the server prints.
3. On each other computer, run:
   ```
   python client.py --server <server IP>
   ```
4. In the client, register:
   ```
   register <name> <role>
   ```
   The role is SUBSCRIBER, PUBLISHER or BOTH.
5. Subscribe to alerts:
   ```
   subscribe <location> <category>
   ```
   For example: `subscribe HALL FIRE`
6. To unsubscribe:
   ```
   unsubscribe <location> <category>
   ```
7. To de-register:
   ```
   deregister
   ```
8. To exit:
   ```
   quit
   ```
