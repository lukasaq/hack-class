looking for users added to  groups

given
The following query looks for event codes related to user group modification for the local Administrators group:

event.code:(4728 or 4732 or 4746 or 4751 or 4756 or 4761)

outcome

![image](https://github.com/user-attachments/assets/3257e023-6767-42f2-a03e-a66e62db9c77)


event.code:1 and process.command_line.keyword~ localgroup

outcome

![image](https://github.com/user-attachments/assets/8399310b-71e9-4b30-8501-ad3f23a1375d)


my way

![image](https://github.com/user-attachments/assets/c6f2a16d-ba04-418e-993f-b6ca2739d91f)
