Python Overview
Python.org describes Python as an “interpreted, object-oriented, high-level programming language with dynamic semantics.” Python is a free, open-source, and easy-to-learn syntax that enables users to quickly develop and test code with little downtime. Python also offers a modular design, where portions of the code are broken down into separate sections that are easier to work with. Python's syntax and modular design make it an attractive choice for cyber defenders.

﻿

Python Variables
﻿

Python is similar to other programming languages in how it uses variables to store and manipulate objects. A variable is a name attached to an object to help create efficient and organized code. Most programming languages require variables to be defined in advance of their use and to remain static with their definition. Python creates efficiency by allowing variables to be both defined and used within the same line of code. Additionally, Python allows variables to change the type of data they define. For example, a variable may start by defining a string value. However, the variable may be changed to a number value at a later time. 

﻿

Figure 13.1-1, below, provides four key principles for creating variables:

﻿

﻿

Figure 13.1-1﻿

﻿

The syntax for creating variables is variable_name = value. The first line in the following example defines the variable named x with the value America!. The second line in the example uses the function print() with the defined variable, which outputs its value on the next line:

x = "America!"
print(x)
America!
﻿

Additional Resources
About Python: https://www.python.org/doc/essays/blurb/ 

﻿ Python Doc uments: https://www. python.org/doc/  ﻿

Data Types
Variables define and store different data types. Data types define data structure and functionality. Python uses specific operators to designate a specific function or manipulation for different data types. Table 13.1-1, below, displays Python's built-in operators for each of the available data types, which are explained next.

﻿

﻿

﻿

Table 13.1-1﻿

﻿

String
﻿

Strings include sequences of text, characters, or data. They are defined by the operator str and written in either single or double quotes. The following example defines the string value as Hello and outputs this value with the function print():

output = str("Hello")
print(output)

Hello
﻿

Numeric
﻿

The numeric data type includes data related to numbers, such as integers, floating point numbers, and complex numbers.

﻿

Integers
﻿

Integers are whole numbers that are defined by the operator int. The following example defines the integer value 10 for the variable output:

output = int(10)
print(output)
10
﻿

Floating Point Numbers
﻿

A floating point number is a number with a decimal point. These numbers are defined by the operator float. The following example defines the floating point number 10.1 for the variable output:

output = float(10.1)
print(output)
10.1
﻿

Complex Numbers
﻿

Complex numbers are imaginary numbers that are defined by the operator complex. The following example defines the complex number 10.j for the variable output:

output = complex(10.j)
print(output)
10.j
﻿

Sequence
﻿

The sequence data type defines a specific order of items that may or may not be changed, depending on the specific sequence type. Sequence types include lists, tuples, or ranges of objects. 

﻿

Lists
﻿

Lists are a group of items, which may include different types of data. The data in lists can be changed whenever necessary. Lists are defined by the operator list, while their items are placed in square brackets. The following example defines a list that includes apple, orange, and 10 for the variable y:

y = list(["apple", "orange", 10])
print(y)
['apple', 'orange', 10]
﻿

Tuples
﻿

Tuples are a list of items that cannot be changed after they are defined. They are defined by the operator tuple, while their items are placed in a subset of parentheses. The following example defines the list apple, orange, and 10 as a tuple for the variable z:

z = tuple(("apple", "orange", 10))
print(z)
('apple', 'orange', 10)
﻿

Older versions of python use the tuple method to list items as shown here. As python has evolved and updated, variables can be quickly defined simply by using brackets. The remainder of the lesson defines variables with brackets. 

﻿

Ranges
﻿

Ranges define numeric sequences. They use the operator range in the syntax range(start, stop, step). The parameters in this syntax are user-defined and indicate the following:

start: The first number included in the sequence.
stop: The number at which the sequence ends. This number is excluded from the sequence.
step: The number that defines the difference between the numbers in the sequence. 
﻿

The following example defines the variable x as a range of numbers that start at 0. The example prints every number counted by 1, until it reaches 5 and stops printing:

x = range(0,5,1)
for n in x:
print(n)
0
1
2
3
4
﻿

Python 2 and Python 3 both use the operator range, but in different ways. In Python 2, the operator range returns one number at a time, as needed. This is an inefficient use of resources. Python 2 also offers the operator xrange, which returns the generator object that displays numbers instantaneously by looping. In Python 3, range replaces the operator xrange and contains all xrange functionality.

﻿

Set
﻿

The set data type stores a collection of unordered items in a single variable. Each item has a unique value and only occurs once in a set. Sets are defined by the operator set, while their items are placed in square brackets. The following example defines the set apple, orange, and 10 for the variable x:

x = set(["apple", "orange", 10])
print(x)

{10, 'orange', 'apple'}
﻿

Frozenset
﻿

Frozensets are sets that are immutable, which means that they cannot be changed after defining them. Frozensets are defined by the operator frozenset and their items are placed in a subset of curly braces. The following example defines the frozenset apple, orange, and 10 for the variable x:

x = frozenset({'apple', 'orange', 10})
print(x)
{10, 'apple', 'orange'}
﻿

Boolean
﻿

Booleans allow a value to be evaluated as either True or False. They are defined by the operator bool. The following example defines the variable x = 10 and y = 11. The variable z uses bool to evaluate whether x is greater than y.

x = 10
y = 11
z = bool(x > y)
print(z)
False
﻿

Binary
﻿

The binary data type manipulates binary data and accesses the memory of binary objects. It uses the operators bytes, bytearray, and memoryview.

﻿

Bytes
﻿

Bytes are defined by the operator bytes. This returns immutable bytes objects initialized with user-defined size and data. The following example creates bytes of the integer size 10 for the variable x.

x = bytes(10)
print(x)
b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
﻿

Bytearray
﻿

Bytearray is defined by the operator bytearray. This operator returns an array of objects in a given number of bytes. The following example creates an array of bytes of the integer size 10 for the variable x.

x = bytearray(10)
print(x)
b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
﻿

Memoryview
﻿

Memoryview is defined by the operator memoryview. It permits objects to access data without having to copy the data. Memoryview is a safe way to expose the buffer protocol in Python. The following example creates memoryview for the variable x = b"10". The output provides access to the internal buffers of the variable x by creating a memory view object.

x = memoryview(b"10")
print(x)
<memory at 0x14ebe21c9a00>
﻿

Modes and Functions
Python is commonly used in interactive mode or through scripts. This section provides additional information about interactive mode, Python scripts, and the Help function that supports development.

﻿

Interactive Mode
﻿

Interactive mode provides an interactive session that immediately displays the output of any code entered. Most languages require code to be compiled before they can be executed, however Python's interactive mode supports real-time code execution with instant output. This means a complex line of code that returns an error may be quickly reviewed, modified, and tested in interactive mode rather than repeatedly compiling the code to test it. Interactive mode is best for writing short lines of code or to examine code line-by-line. 

﻿

Interactive mode may be accessed by opening a new terminal session, then entering the command python, or py. The command prompt indicates that interactive mode is enabled by placing >>> at the start of the entry line. When a command is executed a value is instantly returned. If a command is entered and more code is required to execute the command properly, the command prompt starts a new line with ... immediately after the initial line of code. Interactive mode is exited either by inputting the function quit() into the terminal or by entering Ctrl+D. 

﻿

Scripts
﻿

Python scripts are files containing a logical sequence of orders that execute when called. These scripts use the file extension .py. Python scripts are best for automating time consuming tasks. For example, MITRE’s tool, Caldera, uses Python script automation to help blue teams emulate adversary activity and incident response. Scripting and its capabilities depend on the version of the Python installation. Multiple versions of Python may be installed on a single host. The following command returns the versions:

Python --version
﻿

Functions 
﻿

Within Python, a function is a block of code that is executed when called upon. This section covers two common functions: help() and input().

﻿

Help Function
﻿

The function help() displays Python documentation for components of Python. This function is accessible in interactive mode with the following syntax:

help(object)﻿

﻿

The syntax asks for help for the object in the parentheses. Within Python, an object is a collection of some of the many variables and functions that Python has to offer. The function help() provides easy and efficient access to documentation for each. For example, the following syntax requests help documentation for the function print:

help(print)
﻿

The output from this command returns the following help documentation:

Help on built-in function print in module builtins:

print(...)
    print(value, ..., sep=' ', end='\n', file=sys.stdout, flush=False)

    Prints the values to a stream, or to sys.stdout by default.
    Optional keyword arguments:
    file:  a file-like object (stream); defaults to the current sys.stdout.
    sep:   string inserted between values, default a space.
    end:   string appended after the last value, default a newline.
    flush: whether to forcibly flush the stream.
﻿

Input Function
﻿

The function input() prompts users to enter a specified value. The following example uses the input function to prompt a user for their name and includes a print function to output the name as part of a new string:

x = input('Enter your name:')
print('Hello, ' + x)
﻿

The first output after executing the code above asks the user to enter their name, as follows. In this example, the name entered is User 1: 

Enter your name:
User1
﻿

After entering the name, the second output is returned, as follows:

Hello, User1
﻿
Perform Operations with Python
The following set of labs provides guidance on launching Python in interactive mode, accessing documentation using the function help(), and developing and executing code statements. 

﻿

Check Python Version and Launch Interactive Mode
﻿

Access the terminal emulator, check the Python version, and launch Python in interactive mode.

﻿

Workflow
﻿

1. Log in to the Virtual Machine (VM) lin-hunt-cent using the following credentials:

Username: trainee
Password: CyberTraining1! 
﻿

2. Open Terminal.

﻿

3. Initiate interactive mode on the host by entering the following command:

python
﻿

Completing step 3 outputs the following:

Python 3.9.10 (main, Feb  9 2022, 00:00:00) 
[GCC 11.2.1 20220127 (Red Hat 11.2.1-9)] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> 
﻿

The first line of the output displays Python 3.9.10, which is the version number of the Python installation. Version 3.9.10 is a recent version of Python. Not all hosts may be equipped with a recent version, which means that some features may not be available. Python documentation by version is available in the additional resources section of this task. 

﻿

The last line displays >>> to indicate that Python is in interactive mode. 

﻿

Access Python Help Documentation
﻿

Use Python’s interactive mode to access the help function and find documentation on two Python functions. Continue working in Terminal, in the 

VM lin-hunt-cent.

﻿

Workflow
﻿

1. Within interactive mode, enter the help function by entering the following command:

help()
﻿

This step returns the following output:

Welcome to Python 3.9's help utility!

If this is your first time using Python, you should definitely check out the tutorial on the Internet at https://docs.python.org/3.9/tutorial/.

Enter the name of any module, keyword, or topic to get help on writing Python programs and using Python modules. To quit this help utility and return to the interpreter, just type "quit".

To get a list of available modules, keywords, symbols, or topics, type "modules", "keywords", "symbols", or "topics". Each module also comes with a one-line summary of what it does; to list the modules whose name or summary contain a given string such as "spam", type "modules spam".
﻿

The input line on the terminal is updated with help> to indicate that the help function interface is active. This interface allows queries for documentation stored within Python. 

﻿

2. Display any available documentation related the data type integer by entering the following command:

help> int
﻿

The displayed documentation includes the syntax, subclasses, methods, and data descriptors associated with the data type integer.

﻿

3. Exit the help documentation by entering q﻿

﻿

Exiting the help documentation returns the terminal to the help function interface, as indicated by the help> at the beginning of the line.

﻿

4. Display documentation for the function print by entering the following command:

help> print
﻿

5. Exit the help documentation by entering q﻿

﻿

6. Exit the help function and return to interactive mode by entering the following command:

help> q
﻿

Perform Operations with Python
﻿

Use Python’s interactive mode to complete operations and store the results in a variable. Continue working in Terminal, in the VM lin-hunt-cent.

﻿

Workflow
﻿

1. Within interactive mode, solve a simple equation by entering the following operation:

1 + 1
﻿

This outputs the value 2. Python is a useful development language for solving equations. In interactive mode, the output is returned instantly after entering the operation.

﻿

2. Solve an equation that requires multiple calculations by entering the following operation:

5 * (10 + 5)
﻿

This outputs the value 75. 

﻿

3. Create a variable x and define it as an equation by entering the following command:

x = 5 * (10 + 5)
﻿

This command indicates that the solution to the equation 5 * (10 + 5) is the value of variable x.

﻿

4. Display the value of variable x by entering the following command:

print(x)
﻿

Printing the variable x outputs 75. This confirms that the variable x holds the value of the equation 5 * (10 + 5). This variable only carries the value 75 while the current Python session in interactive mode is available. However, after terminating the current session, this data about variable x no longer exists. 

﻿

5. Define the variable y as a string value by entering the following command:

y = "Hello, World!"
﻿

Executing this command assigns the text Hello, World! as the value for variable y.

﻿

6. Perform string slicing on the variable y by entering the following command:

print(y[7:13])
﻿

This command prints a “slice” of the entire string value for variable y. The slice specified consists of characters 6 through 12. The command outputs the following:

World!
﻿

7. Store the value from the string slicing as a variable by entering the following command:

z = (y[7:13])
﻿

The command defines variable z as a string that is composed of characters 6 through 12 from the variable y. 

﻿
Program Flow Control
Specific Python syntax is available to enable developers to control code execution, its order, timing, and duration. These features are referred to as Python flow control. Common flow controls include code blocks, conditional statements, boolean logic, and loops. These are each detailed below. 

﻿

Code Blocks
﻿

A code block in Python is a piece of program text that is executed as a unit. An application consists of multiple blocks of code. This is similar to written essays that consist of multiple paragraphs. Code blocks are defined by indented formatting and new code blocks are established by creating new indent levels. 

﻿

Below is an example of two code blocks. The indent on the second line indicates that a code block has started from the previous line (line 1). The block continues by maintaining its indent level for two more lines, until the indent returns back to the original level. The second code block follows a similar format.

def code1(): 
	x = 3 #same block
	y = x + 6 #same block
	print(y) #same block
def code2():
	x = 10 #new block
	y = x + 6 #new block
	print(y) #new block
﻿

Conditional Statements
﻿

A conditional statement evaluates whether two values meet a specific condition. After an evaluation determines that the condition exists, the next line of code is executed. Python provides built-in functionality to implement conditional statements. The logical conditions supported by Python use the following syntax:

Equals: x == 7
Not Equals: x != y
Less than: x < y
Less than or equal to: x <= y
Greater than: x > y
Greater than or equal to: x >= y
﻿

The following code is an example of designing a Python conditional statement. The code starts by defining the variables x and y, then uses the operator if to initiate a conditional statement. The statement evaluates whether the variable x has a value less than the variable y. 

x = 10
y = 560
if x < y:
  print("x is less than y")
﻿

If this condition is true, the code prints the specific string of text defined in the example. If the condition is false, the command prompt does not return anything and, instead, returns the entry line to >>>. In the above example, the variable x has a value of 10. Since this is less than variable y, which has a value of 560, the statement is true. Executing this code returns the following output:

x is less than y
﻿

Boolean Logic
﻿

Boolean statements return either True or False. They are similar to conditional statements because both compare values of objects. Code that uses a Boolean statement executes based on the True or False logic the comparison returns. 

﻿

The following is an example of a Python conditional statement that uses Boolean logic. It uses the operators if and else to initiate the statement. Similar to the last example, the statement starts by evaluating whether the variable x is less than the variable y. If this is true, it prints the text "x is less than y". If the variable x is not less than the variable y, it prints the text "x is not less than y". 

x = 10
y = 560
if x < y:
  print("x is less than y")
else:
  print("x is not less than y")
﻿

Loops
﻿

Loops in programming languages allow users to repeatedly execute code for a defined number of intervals. Python supports for loops and while loops.

﻿

for Loops
﻿

A for loop uses the operator for to iterate on an object. In the example below, the code iterates through the range, printing each number until it reaches the value of x:

x = 4
for i in range(0, x):
  print(i)
﻿

When the variable i reaches the value of variable x, it stops printing. This is why this code only outputs up to the number 3:

0
1
2
3
﻿

while Loops
﻿

A while loop uses the operator while to execute a block of conditional statements until a specific condition is met. In the example below, the code executes until the variable x < 3 is no longer true. At the end of each loop, x increases by 1 and the new value for x is used in the next loop.

x = 0
while (x < 3):
  print("Loop")
  x += 1
﻿

The variable x loops until its value becomes 3. At that point, x is no longer less than 3, so the while loop stops printing. This code outputs Loop three times:

Loop
Loop
Loop




Examine the following Python code:
x = 0
while (x < 5):   
     print("Loop")
	x += 1


x = 0
while (x < 5):   
     print("Loop")
	x += 1

Workflow


1. Log in to the VM lin-hunt-cent using the following credentials:
Username: trainee
Password: CyberTraining1! 



2. Open Terminal.


3. Initiate interactive mode running on the host by entering the following command:
python



4. Define two variables (a and b) by entering the following commands: 
a = 45
b = 21



5. Use the operator if to create a conditional statement that evaluates a and b by entering the following command:
if a > b:
...	  print("a is greater than b")



NOTE: To execute the command in step 5, an indent must be inserted prior to the print("a is greater than b") portion of the code and you must press Enter.


6. Select Enter.


The conditional statement proves true because 45 is greater than 21. This returns the following output:
a is greater than b



Develop a Conditional Statement with Boolean Logic


Use Python’s interactive mode to develop conditional statements using Boolean logic. Continue working in the same Terminal session as the previous workflow, in the VM lin-hunt-cent.


Workflow


1. In the current Terminal session, create a Boolean statement by entering the following operation:
if a < b:
  print("a is less than b")
else:
  print("a is not less than b")



This statement uses the operator if to evaluate whether variable a is less than variable b. If this condition is true, it prints the string a is less than b. If the condition is false, it prints the string a is not less than b. 


Since 45 is not less than 21, the condition in the statement is evaluated as false. Executing this operation returns the following output:
a is not less than b



Develop a for Loop


Use Python's interactive mode to develop a loop using the operator for. Continue working in the VM lin-hunt-cent.


Workflow


1. Open a new terminal session and access Python in interactive mode. 


2. Define a new value for variable x by entering the following command: 
x = 7



3. Define a range for the variable i with the operator for, by entering the following command:
for i in range(1,x):
  print(i) 



The for loop in the code executes until x, in the range(1,x) is reached. When the variable i reaches 7, the code stops printing. This outputs the following six digits for i:
1
2
3
4
5
6



Develop a while Loop


Use Python's interactive mode to develop a loop using the while operator. Continue working in the same Terminal session as the previous workflow, in the VM lin-hunt-cent.


Workflow


1. In the current Terminal session, create a while loop by entering the following operation:
counter = 0
while counter < 3:
  print("inside loop")
  counter += 1
else:
  print("outside loop")



The while loop in the code executes until the variable counter is no longer less than 3. For every loop completed, Python adds an integer value of 1 to the variable, and then continues the loop. When the variable counter is no longer less than 3, the loop completes the else command and ends the loop. 


The variable counter reaches a value that is no longer less than 3 after executing three times. Thereafter, the else statement is executed. This results in the following output:
inside loop
inside loop
inside loop
outside loop

Determine Combinations in Python
Python lists are appropriate for storing the Users and Hosts data since each list is composed of strings. 

﻿

Determine Combinations with Python
﻿

Use Python to write code that produces all possible combinations of users and hosts from the lists provided. Then, use the skills and information from this and previous lessons to complete the workflow and answer the following series of questions.

﻿

Workflow
﻿

1. Log in to the VM lin-hunt-cent using the following credentials:

Username: trainee
Password: CyberTraining1! 
﻿

2. Open a new Terminal session.

﻿

3. Access Python's interactive mode. 

﻿

4. Define the variables users and hosts with the following commands: 

users = ['user47', 'user71', 'user82', 'user93']

hosts = ['wks6', 'mailserver', 'kali2', 'centos3', 'ftp', 'www']
﻿

Two loops are required to find every combination of the Users and Hosts lists. Each loop requires a new variable, the variable x and the variable y. The variable x is associated with the Users list. The variable y is associated with the Hosts list. The following code prints every combination of users and hosts:
users = ['user47', 'user71', 'user82', 'user93']
hosts = ['wks6', 'mailserver', 'kali2', 'centos3', 'ftp', 'www']
for x in users:
  for y in hosts:
    print(x,y)



The code executes, pairs objects from x (users) with objects from y (hosts), and prints each pair along the way. After reaching all possible combinations of objects, the code stops executing. This returns the following output:
user47 wks6
user47 mailserver
user47 kali2
user47 centos3
user47 ftp
user47 www
user71 wks6
user71 mailserver
user71 kali2
user71 centos3
user71 ftp
user71 www
user82 wks6
user82 mailserver
user82 kali2
user82 centos3
user82 ftp
user82 www
user93 wks6
user93 mailserver
user93 kali2
user93 centos3
user93 ftp
user93 www
















































































 
