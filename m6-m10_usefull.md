Run the following query to search for scanning behavior:

event.dataset:conn and source.ip:199.63.64.51 and ((client.packets>=1 and client.packets<=3) and server.packets<=1)

![image](https://github.com/user-attachments/assets/931358f3-7636-4ea6-8b85-a4ea435b861e)
