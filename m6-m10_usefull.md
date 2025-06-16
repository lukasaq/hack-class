Run the following query to filter for only Zeek connection logs.

event.dataset:conn

Toggle the following fields:

source.ip 

destination.ip 

destination.port 

connection.state

client.packets

server.packets


![image](https://github.com/user-attachments/assets/5df234ea-0198-4c45-8c6b-01dcd9a5a0fd)



Run the following query to search for scanning behavior:

event.dataset:conn and source.ip:199.63.64.51 and ((client.packets>=1 and client.packets<=3) and server.packets<=1)

![image](https://github.com/user-attachments/assets/931358f3-7636-4ea6-8b85-a4ea435b861e)


Filter for HTTP logs by running the following query:

event.dataset:http

Toggle the following fields:

source.ip

destination.ip

http.status_code

http.uri

http.request.body.length

http.response.body.length


![image](https://github.com/user-attachments/assets/f9b0dd53-f275-42c3-a4b9-28569e052cc6)

