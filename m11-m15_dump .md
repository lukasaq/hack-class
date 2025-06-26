Python Data Structures
Python data structures organize data by type, which allows greater efficiency when accessing the data. The four basic Python data structures include the following:

Lists

Sets

Tuples

Dictionaries

﻿

Everything in Python is an object, including data structures. An object is "mutable" if its value can change. The object is "immutable" if its value cannot be changed. Whether or not an object's value can change helps determine the best use case for each type of data structure.

﻿

Lists
﻿

A list is an ordered collection of data. To create a Python list, place the items in square brackets and separate each item with commas. The following example defines the variable numbers as a list of numerals from 1 through 5 using this syntax:

numbers = [1, 2, 3, 4, 5]
﻿

Lists are mutable because items can be added and removed from the list at any time. However, the order of items in a list does not change. Items retain their order in the list, for as long as the list is available. The order uniquely defines each item in the list by an index starting at zero. In the following example, the item 3 can be removed, however the order still remains as per the original example from above:

numbers = [1, 2, 4, 5]
﻿

Table 13.2-1, below, presents common operations for interacting with Python lists.

﻿

﻿

Table 13.2-1﻿

﻿

Looping Lists
﻿

Python supports iterating over a list using for loops, while loops, and comprehensions. A for loop iterates over a list before performing a given action. A for loop completes a loop over each item in the list unless it is explicitly stopped. The following example uses the list numbers, from the previous example, and a for loop to print each item from the list:

# Looping Over a List in Python with a For Loop
numbers = [1, 2, 3, 4, 5]

for number in numbers:
    print(number)

#Output
1
2
3
4
5
﻿

A while loop continues to iterate until it meets a specified set of conditions. The following example uses the function len to return the length of the list. The while loop directs Python to continue to print i, as long as it is less than the length of the list. 

numbers = [1, 2, 3, 4, 5]

# Get length of list using len() function
length = len(list)
i = 0

while i < length:
    print(list[i])
    i += 1

#Output
1
2
3
4
5
﻿

Python comprehensions are a compact way of iterating over a list. The following example uses a comprehension to print out each item from the list numbers. A list comprehension only requires one line of code, and does not need a for or while loop to iterate over the list.  

# Using List Comprehensions to Iterate Over a List
numbers = [1, 2, 3, 4, 5]
[print(number) for number in numbers] 

#Output
1
2
3
4
5
[None, None, None, None, None]
﻿

Tuples
﻿

Python tuples are similar to Python lists. They are both built-in data structures for ordered collection of objects. However, tuples have more limited functionality than lists. Lists are mutable whereas tuples are immutable. Data that is not intended to be modified should be stored in tuples. This prevents accidental deletion or modification. 

﻿

Tuples are created by placing a sequence of values, separated by commas, in parentheses. The following example follows this syntax to define the variable tuple_1 as a tuple:

tuple_1 = ("blue", "green", "yellow", 10)
﻿

Python provides a powerful tuple feature that assigns the right-hand side of values to the left-hand side of values. This is referred to as "unpacking". Unpacking extracts tuple values and combines them into a single variable. The example x, y = (1, 2) uses tuple syntax to assign the values on the right side (1, 2) to each variable on the left side (x, y), based on the position of each value. This defines the variables as x = 1 and y = 2. 

﻿

Another way to use this feature is to assign each item in a tuple to a new variable. The following example assigns three values to the variable info. It then assigns three new variables to each tuple value in info by listing each new variable in order of its matching value. Printing each new variable displays the new assignments:

info = ("Kathy Simpson", "Marketing", "Senior")
(name, department, level) = info

print(name)
print(department)
print(level)

#Output
Kathy Simpson
Marketing
Senior 
﻿

Dictionaries
﻿

Python dictionaries have different traits, depending on the Python version in use. In Python 3.6 and earlier, a dictionary data structure is an unordered collection of data values that stores data in a key: value format. From Python version 3.7 and later, dictionaries are ordered collections. Similar to lists, dictionaries are mutable and dynamic, so they can grow or shrink as needed. Dictionary values are accessed through their keys, rather than by their positions.

﻿

A dictionary is defined by enclosing a comma-separated list of key: value pairs in curly braces {}, as follows:

dictionary = {
    key: value,
    key: value,
    key: value
}
﻿

Below, Table 13.2-2 presents common operations for interacting with dictionaries. In these examples, x is the name of the dictionary.

﻿

﻿

Table 13.2-2﻿

﻿

Python allows iterating through both the keys and values in a dictionary. The syntax for iterating is dictionary.items() where dictionary is the name of the dictionary to iterate through. This returns one key: value pair, at a time. The following example defines the dictionary dict, then defines the variable items with the iterating syntax. This iterates through the dictionary items when printed:

dict = {'name': 'Jeff', 'age': '25', 'address': 'New York'}
items = dict.items()
print(items)
dict_items([('name', 'Jeff'), ('age', '25'), ('address', 'New York')])

#Output
dict_items([('name', 'Jeff'), ('age', '25'), ('address', 'New York')])
﻿

Python also allows iterating through either just the keys or just the values in a dictionary, rather than iterating through pairs. Iterating through dictionary keys uses the syntax dictionary.keys() to return an object containing all the dictionary keys. Iterating through dictionary values uses the syntax dictionary.values() to return only the values in a Python dictionary. In the following example, the variable items1 is defined with the syntax to iterate through only the keys and the variable items2 is defined with the syntax to iterate through only the values:

dict = {'name': 'Jeff', 'age': '25', 'address': 'New York'}
items1 = dict.keys()
print(items1)
#Output
dict_keys(['name', 'age', 'address'])

#Using dictionary.values
items2 = dict.values()
print(items2)
#Output
dict_values(['Jeff', '25', 'New York']) 
﻿

Sets
﻿

A set is a unique collection of data that stores multiple items in a single variable. Sets are unordered, cannot be modified, and do not have indexes. A set is used when the existence of the data is more important than its order. Items may be added or removed in a set, but they cannot be modified. Items in a set must have unique values. The following is an example of a Python set with three items:

set_a = {"item 1", "item 2", "item 3",}


Python Multidimensional Arrays
An array is a vector that contains elements of the same data type. For example, an array may contain only characters, only integers, or only floating-point numbers. Arrays are different from lists because arrays need to be declared, while lists do not. Arrays are also preferred for storing large amounts of data because they are more compact and efficient. Additionally, arrays are inherently capable of numerical operations.

﻿

A type code is a single character that specifies the type of object an array stores when creating the object. In the Python Type column int stands for integer. The type float stands for floating-point numbers, which are numbers that include decimal points. Table 13.2-3, below, contains the type codes used by the Python module array.

﻿

﻿

Table 13.2-3﻿

﻿

The syntax for the Python module array is as follows:

import array
array.array(typecode[, initializer])
﻿

Multidimensional Lists and Arrays
﻿

Python supports multidimensional lists and arrays. A multidimensional object defines and stores data in a format with more than two dimensions. 

﻿

A multidimensional array is a two-dimensional array that has more than one row and column. To identify the position of an element in a multidimensional array, two indexes should be specified instead of only one. This can be done by fitting a list inside of another list, which is also known as a "nested" or multidimensional list. A multidimensional list takes the form of a basic list, such as List = [1, 2], but includes other lists as elements in the following way:

List = [[1, 2], [3, 4], [5, 6]]
﻿

A multidimensional array can be created by passing two or more lists of elements to the function. This type of array is created using the list class of Python, rather than the Python array class. The following example nests two list items within a single list to define the array:

array = [[1, 2, 3, 4], [5, 6, 7, 8]]

#Output
print(array)
[[1, 2, 3, 4], [5, 6, 7, 8]]
print(type(array))
<class 'list'>
﻿

Arrays in list format can also be developed in a two step process. First, each row is defined as a standalone list. Second, an array groups the rows together, in its own list. The example below follows this procedure by defining three rows, then implementing the array:

row1 = [0, 0, 0, 0, 0]
row2 = [0, 0, 0, 0, 0]
row3 = [0, 0, 0, 0, 0]

array = [row1, row2, row3]
﻿

The array can then be accessed with a for loop, as follows:

for row in array:
print (row)
﻿

Create Python Arrays
﻿

Use an interactive Python prompt to create multiple arrays, then access individual elements of each array.

﻿

Workflow
﻿

1. Log in to the Virtual Machine (VM) lin-hunt-cent using the following credentials:

Username: trainee
Password: CyberTraining1! 
﻿

2. Open a Linux terminal.

﻿

3. Launch an interactive python prompt with the following command:

python
﻿

4. Create a multidimensional array by placing values between the square brackets, using the following syntax:

array = []
﻿﻿﻿

5. Display the initialized empty array by entering the following:

print (array)
﻿

﻿Figure 13.2-1

﻿

6. Create Python lists by entering the following:

List = [1, 2, 3, 4]
List1 = [5, 6, 7, 8]
List2 = [9, 10, 11, 12]





7. Add the newly created lists to the array with the following syntax:

array = [List, List1, List2]
﻿

8. Iterate through the array with a for loop, as follows:

for list in array:
...	print(list)
﻿

9. Submit the enter key twice to return the output.

﻿

﻿

Figure 13.2-2

﻿

10. Iterate through a specific list within the array by creating a for loop, as follows:

for list in array:
	print(List2)
﻿

11. Submit the enter key twice to return the output.



﻿

Figure 13.2-3

﻿

12. Create rows in Python with the following code: 

row1 = [0, 0, 0, 0]
row2 = [0, 0, 0, 0]
row3 = [0, 0, 0, 0]
﻿

13. Create a new array made of the rows by entering the following:

array1 = [row1, row2, row3]
﻿

14. Use a for loop to iterate through array1.

for row in array1:
...     print (row)

﻿

Figure 13.2-4


Use the information from this lab to answer the next question.

Create and Edit a Python Dictionary
The previous lab ran Python statements in an interactive prompt. This next lab creates a Python script using the Vim text editor, then executes the script from the shell command line. This lesson uses the following common commands for the Vim text editor:

Entering i enables insert mode, which allows text to be written to the file.

Using the escape key (esc) while in insert mode returns Vim to normal mode. 

Entering :wq in normal mode saves and exits the file.

﻿

Create a Python Dictionary
﻿

Create a dictionary from scratch and populate data into the dictionary. Then, execute the script to display the output. Use the common Vim commands listed above, as needed.

﻿

Workflow﻿

﻿

1. Log in to the VM lin-hunt-cent using the following credentials:

Username: trainee
Password: CyberTraining1!
﻿

2. Open a Linux terminal.

﻿

3. Create the file dictionary.py in Vim by entering the following command:

vim dictionary.py
﻿

4. Display line numbers for Vim by entering the following command: 

:set number
﻿

5. Create a new dictionary by adding the following text on line 1:

new_dictionary = {}
﻿

6. Print the empty dictionary by entering the following text on line 3:

print(new_dictionary)
﻿

Figure 13.2-5

﻿

The syntax print() prints the output from the command to the shell. The item to print is placed within the parentheses of the print() syntax. In step 6, the item in parentheses is the variable that was assigned for the dictionary. 

﻿

7. Print the type of data structure that was just created by entering the following text on line 5:

print (type(new_dictionary))
﻿

The code added to line 5 identifies the data structure used in the script, which is useful when the data structure is unknown. It is important to identify the correct data structure when working with Python because each data structure has a different use case.

﻿

8. Save the script and exit Vim by entering the following:

:wq
﻿

9. Execute the script by entering the following command:

python dictionary.py

﻿

Figure 13.2-6

﻿

Edit a Python Dictionary
﻿

Continue working in the Linux terminal using the VM lin-hunt-cent. Create a Python dictionary, then iterate through the dictionary to display its contents. Edit the Python script and append data to the existing dictionary.

﻿

Workflow
﻿

1. Create a new file, testresults.py in Vim by entering the following:

vim testresults.py
﻿

2. Create a dictionary named test_results and populate data into it by adding the following text on line 1:

test_results = {"Frank":"Passed", "Corey":"Passed", "Daniel":"Failed"}
﻿

3. Iterate through the dictionary and display only the values in its key:value pairs by adding the following text on lines 3 and 4:

for results in test_results.values():
		print(results)
﻿

Figure 13.2-7

﻿

Displaying only the values in a dictionary is useful when the keys do not need to be displayed. The example above displays only the test results (values), and omits the names of those who took the test (keys).

﻿

4. Save the Python script and exit Vim by entering the following: 

:wq
﻿

5. Execute the script by entering the following command:

python testresults.py


﻿

Figure 13.2-8

﻿

6. Open the file testresults.py with Vim. 

﻿

7. Remove the code on lines 3 and 4.

﻿

8. Add an item to the dictionary by entering the following text on line 3:

test_results["Alexandra"] = "Failed" 
This method appends a new key:value pair to the existing dictionary.

﻿

9. Print the output when the script is executed by adding the following text on line 5:

print(test_results)
﻿

﻿Figure 13.2-9

﻿

10. Save the Python script and exit Vim by entering the following:

:wq
﻿

11. Execute the script by entering the following command:

python testresults.py
﻿

﻿Figure 13.2-10

﻿

Use the information from these labs to answer t he following  question.



Create and Edit a Python List
Create a list and populate data into the list. Then, edit the list and add another item to it. 

﻿

Workflow
﻿

1. Log in to the VM lin-hunt-cent using the following credentials:

Username: trainee
Password: CyberTraining1!

2. Open a Linux terminal.

﻿

3. Create the file grocerylist.py with Vim, by entering the following command:

vim grocerylist.py
﻿

4. Create a new list by adding the following text on lines 1 and 2:

groceries = ["apples", "milk", "chicken", "bread"]
prices = ["2.99", "3.60", "10.99", "3.10"]
﻿

5. Print the output of the script by entering the following text on lines 4 and 5:

print(groceries)
print(prices)
﻿

Figure 13.2-11

﻿

6. Save the Python script and exit Vim by entering the following:

:wq
﻿

7. Execute the script with the following command:

python grocerylist.py

﻿

Figure 13.2-12﻿

﻿

8. Open the file grocerylist.py with the Vim text editor.

﻿

9. Remove the print items on lines 4 and 5.

﻿

10. Add an item to the list groceries by entering the following text on line 3:

groceries.append("oranges")
﻿

The above code adds an item to the already existing list groceries. The syntax to append an item to an existing list is listname.appened("item"). It is also possible to add multiple items to a list using the following syntax:

listname.extend(["item1", "item2", "item3"])
﻿

11. Iterate through the list groceries and display the list in a more readable format by adding the following text on lines 5 and 6:

for number in groceries:
	print(number)
﻿

The code in step 11 uses a for loop to iterate over each item in the list. It uses the word number to make the code cleaner and easier to view.

﻿

﻿

﻿Figure 13.2-13﻿

﻿

12. Save the Python script and exit Vim by entering the following command:

:wq
﻿

13. Execute the Python script by entering the following command:

python grocerylist.py
﻿

Figure 13.2-14


Use this information to answer the following quest ion. ﻿

Click "Finish" to exit the event.


Combine Python Data Structures
Create an empty dictionary, then create lists and populate the lists with data. Combine the two data structures to create a dictionary that contains Python lists, then add a new list into the existing data structure.

﻿

Workflow
﻿

1. Log in to the VM lin-hunt-cent using the following credentials:

Username: trainee
Password: CyberTraining1!
﻿

2. Open a Linux terminal. 

﻿

3. Edit the Python file employeedata with Vim by entering the following:

vim employeedata.py
﻿

4. Create a dictionary named employees on line 1, by entering the following:

employees = {}
﻿

5. Add a list into the dictionary in the key:value format by entering the following text on lines 3 and 4:

employees["Name"] = ["Chuck", "Emily", "Max", "Laura"]
employees["Age"] = ["35", "25", "42", "55"]
﻿

The values step 5 uses for each key:value pair are entered as Python lists. Python allows lists for dictionary values, but not for dictionary keys.

﻿

6. Print the output by adding the correct print function on line 6:

print(employees)
﻿

7. Create a new list named new_employees by entering the following on line 5 (before the print function):

new_employees = ['Sam', 'Frank', 'Amy']
﻿

8. Append new_employees as a sublist of the dictionary by adding the following line between the new_employees list and the print function:

employees["Name"].append(new_employees)
﻿

﻿Figure 13.2-15﻿

﻿

9. Execute the python script so that it outputs the following:

#Output
{'Name': ['Chuck', 'Emily', 'Max', 'Laura', ['Sam', 'Frank', 'Amy']], 'Age': ['35', '25', '42', '55']}
﻿

There are two sets of square brackets [] in the output for Name, after appending the new list to the existing list in the dictionary. The inner set surrounds the new list, while the outer set surrounds all items in the Name list.

﻿





























