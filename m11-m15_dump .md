
Test a Python Function
One trait Python shares with other high-level programming languages is that it has a defined syntax for constructing commands. Commands are constructed with components known as functions, similar to how a cooking recipe is made of different ingredients.  The functions allow Python to execute programs and reuse code. 

﻿

Python Function Overview
﻿

A Python function is a block of code that performs a certain action. The following is an example of the Python function print_text, which prints a statement that passes the string Hello World! to standard output:

def print_text():
  print("Hello World!")
﻿

In the function print_text, the keyword def is placed before the function name. Keywords are necessary for defining the function in Python.

﻿

Test a Python Function
﻿

Test the performance of a Python function within a script.

﻿

Workflow
﻿

1. Log in to the Virtual Machine (VM) lin-hunt-cent using the following credentials:

Username: trainee
Password: CyberTraining1!
﻿

2. Open Terminal.

﻿

3. Open an empty text editor within Terminal by entering the following command:

[trainee@lin-hunt-cent ~]$ vim hello.py
﻿

4. Set the text editor to Insert mode by entering the letter i﻿

﻿

5. Enter the following function into the text editor:

def print_text():
  print("Hello World!")

print_text()
﻿

The function in step 5 is similar to the example from the previous section, but with one difference. Step five adds the command print_text() to the last line of the code to call the defined function during script execution.

﻿

6. Exit the text editor’s Insert mode by entering the ESC key.

﻿

7. Exit the text editor while saving changes to the script hello.py by entering the following command:

:wq
﻿

8. Run the Python script by executing the following command:

[trainee@lin-hunt-cent ~]$ python hello.py
﻿

The output is as follows:

Hello World!

﻿

This output indicates that the function print_text() correctly executed and printed the statically-defined text string to the screen. This is basic function performance. Upcoming labs in this lesson explore more complex functions that print different types of strings.

﻿

The next series of tasks in this lesson introduce the following additional components of Python functions:

Parameters
Arguments
Multiple Arguments and Parameters
Returning Values
﻿
Parameters and Arguments
Parameters
﻿

The function in the previous lab is efficient for printing only the specific text string, Hello World!. This code has limited reusability because the text string printed by this function cannot be modified. This limits its use to only those occasions where printing Hello World! is valuable. One way to improve the reusability of this code is to have a variable define the string to be printed, rather than having the string hard-coded and contained within the function itself. The approach allows different string variables to be passed to the function and make the action of printing more dynamic. Such variables are known as parameters and they are included in the function definition.

﻿

The following revision to the function print_text replaces the string Hello World! with the parameter msg:

def print_text(msg):
  print(msg)
﻿

This revision makes the code more reusable since the string to print is no longer hard-coded into the function. Instead, the string is accepted as a parameter when the function print_text is called.

﻿

Since the value of the parameter msg is not defined in the function print_text, a value must be passed from elsewhere in the Python program or else this function results in an error. 

﻿

View a Parameter Error
﻿

Observe the error that results when the value of a parameter is missing.

﻿

Workflow
﻿

1. Enter the VM lin-hunt-cent. If necessary, enter the following credentials:

Username: trainee
Password: CyberTraining1!
﻿

2. Open Terminal.

﻿

3. Open the Python script hello.py in the text editor by entering the following command:

[trainee@lin-hunt-cent ~]$ vim hello.py
﻿

4. Set the text editor to Insert mode by entering the letter i﻿

﻿

5. Modify the function print_text() by replacing the string Hello World! with the parameter msg, as follows:

def print_text(msg):
  print(msg)

print_text()
﻿

6. Exit the text editor’s Insert mode by entering the ESC key.

﻿

7. Exit the text editor while saving changes to the script hello.py by entering the following command:

:wq
﻿

8. Run the Python script by executing the following command:

[trainee@lin-hunt-cent ~]$ python hello.py
﻿

Executing this Python script outputs the following error:

TypeError: print_text() missing 1 positional argument: 'msg'
﻿

The modified function print_text has a new definition which includes the parameter msg. This is why the error from executing this script reports that the function call print_text() is missing one positional argument. In order to satisfy the required msg parameter in the function definition, an argument must be passed within the function call print_text.

﻿

Arguments
﻿

Passing an argument into a function occurs when a previously defined variable name is included within a previously defined function call. In the following script, the first line defines the variable myMsg as Hello World!. The second line is a function call that consists of the name of the previously defined function print_text along with the newly defined variable myMsg.

myMsg = "Hello World!"
print_text(myMsg)
﻿

In this instance, the result of the above function call is Hello World!﻿

﻿

After providing the variable definition and argument in the function call, executing the function no longer produces an error. 

﻿

Pass an Argument into a Function
﻿

Continue working in Terminal, in the VM lin-hunt-cent, to modify the script hello.py so that it successfully executes a function that includes an argument.

﻿

Workflow
﻿

1. In Terminal, open the Python script hello.py in the text editor by entering the following command:

[trainee@lin-hunt-cent ~]$ vim hello.py
﻿

2. Set the text editor to Insert mode by entering the letter i﻿

﻿

3. Modify the function print_text() by defining the variable myMsg and adding an argument so that the function is written as follows:

def print_text(msg):
    print(msg)

myMsg = "Hello World!"
print_text(myMsg)
﻿

4. Exit the text editor’s Insert mode by entering the ESC key.

﻿

5. Exit the text editor while saving changes to the script hello.py by entering the following command:

:wq
﻿

6. Run the Python script by executing the following command:

[trainee@lin-hunt-cent ~]$ python hello.py
﻿

Executing this Python script outputs the following:

Hello World!
﻿

After the argument myMsg is passed along with the function call print_text, the script  execute s without the error seen in the previous lab. This function is also now more reusable since it will print any text string passed to it a s an arg ument. The value of the variable myMsg can be changed to any text string and passed to print_text for printing to the sc reen.


Multiple Arguments and Parameters
A function call can include multiple parameters that make the function more dynamic. In the following example, the function new_print_text calls two parameters, string1 and string2, to be used with a print command:

def new_print_text(string1,string2):
  print(string1,string2)
﻿

The function new_print_text can be used with a couple of variable definitions followed by a function call, as follows:

myMsg1 = "Hello "
myMsg2 = "World!"

new_print_text(myMsg1,myMsg2)
﻿

Executing this function call prints the combined string Hello World!, just as in the previous examples in this lesson. However, changing the sequence of these two arguments so that the variable myMsg2 is listed first provides a different output. Instead of Hello World!, the resulting combined string prints World!Hello. This is an example of positional arguments, where arguments and parameters are linked according to the order in which they are provided.

﻿

In contrast to positional arguments, keyword arguments explicitly define the argument value that corresponds to a function parameter. The following function call prints the string Hello World! because the function parameters are used as keywords that are assigned specific values:

myMsg1 = "Hello "
myMsg2 = "World!"

new_print_text(string2=myMsg2, string1=myMsg1)
﻿

When using keyword arguments, a variable name can be used as shown or a specific value can be given, such as (string2="World!", string1="Hello").

﻿

Similar to keyword arguments, function parameters explicitly define default values when a given argument is not provided. The following function call produces an error because the function new_print_text expects two arguments, while the example below only lists one:

new_print_text(string2=myMsg2)
﻿

A solution to resolve this error is to use a default value. In the following example, the parameter string1 has been set to a default value of This Is My. When the previous function call is made with only string2 defined, this setting prints This Is My World! instead of resulting in an error. 

def new_print_text(string2, string1="This Is My"):
  print(string1,string2)
﻿

Defining a default value for a parameter is useful for correctly executing a function that requires a non-empty value. All default arguments must follow non-default arguments, as in the previous example, otherwise an error results.

﻿

The previously defined functions work well for printing one or two string values. However, code reusability can be improved by adding the ability to print a variable number of string values. For instance, if the string Hello World! We are coding! were to be printed using the function above, it would have to be passed as one string or broken into two strings. Yet, if there was a need to collect multiple single-word strings and combine them into a single string output, there would need to be a function definition that allows up to five parameters. Twenty or one thousand single-word strings would be more complex.

﻿

To allow for a more feasible function definition, a single parameter can be defined with *args. This allows for a variable number of arguments to be passed to the function when called. In the following example of a new function definition, *args is set as the only function parameter which accepts a variable-length argument:

def variable_print_text(*args):
  for i in args:
    print(i)

variable_print_text("Hello","World!","We","are","coding!")
﻿

When the last line of code in this function is called, the function recognizes an argument length of five and iterates through each to print to the screen the phrase Hello World! We are coding!﻿

﻿

Pass Multiple Arguments into a Function
﻿

Modify the script hello.py so that it successfully executes a function that accepts a variable number of arguments. Continue working in Terminal, in the VM lin-hunt-cent.

﻿

Workflow
﻿

1. In Terminal, open the script hello.py in the text editor by entering the following command:

[trainee@lin-hunt-cent ~]$ vim hello.py
﻿

2. Set the text editor to Insert mode by entering the letter i﻿

﻿

3. Edit hello.py to include the following code:

def variable_print_text(*args):
  for i in args:
    print(i)

variable_print_text("Hello","World!","We","are","coding!")
﻿

4. Exit the text editor’s Insert mode by entering the ESC key.

﻿

5. Exit the text editor while saving changes to the script hello.py by entering the following command:

:wq
﻿

6. Run the Python script by executing the following command:

[trainee@lin-hunt-cent ~]$ python hello.py
﻿

Executing the script prints the following:

Hello
World!
We
are
coding!
﻿

The script output shows that each of the arguments passed to the function variable_print_text was successfully printed to the screen, in the order by which it was passed. This indica tes that  the use of *args as a function parameter was successful at accepting multiple argumen ts witho ut the need to explicitly define a separate parameter for each possible ar gument.


Returning Values
Each of the previous functions performed a print without any further interaction with the rest of the Python program. A function can also pass its output to another function or code in a program so that the output can be reused. 

﻿

The following new function is similar to the previous function variable_print_text because it allows a variable number of arguments to pass to the parameter *args. However, this function performs a more complex task than hello.py, which simply prints the provided arguments. The following function prints its arguments in reverse order:

def reverse_text(*args):
  reverse = [None] * len(args)
  counter = len(args) - 1
  for i in args:
    reverse[counter] = i
    counter -= 1

  output = ''
  for i in reverse:
    output += ' ' + i

  return output


phrase = reverse_text("Hello","World!","We","are","coding!")
print(phrase)
﻿

This new function implements the following steps:

A list named reverse is created with as many elements as there are arguments, and filled with dummy data. 
A counter variable is created, which is one less than the number of arguments. Since this counter is used with an index starting from 0, the last value must be one less than the total number of arguments.
The function iterates over the number of arguments and assigns the value of each argument to the reverse list in reverse order.
An empty variable named output is created to store the contents of the reverse list as a single string.
The final line in the function, return output, returns the variable named output back to the line of code that is called the reverse_text function.
﻿

In the code example above, the line which performs the function call is as follows: 

phrase = reverse_text("Hello","World!","We","are","coding!")
﻿

Since calling the function results in returning data, a variable named phrase is set to equal the output of the function. When the print statement in the last line is performed, the result printed to the screen is coding! are We World! Hello, which is the reverse of the input into the function.


Create a Python Function
The previous examples of Python functions in this lesson were written as blocks of code within the context of a Python script, rather than through an interactive Python session. Scripts have several advantages, such as storing Python code to reuse and reference in other Python scripts in the future. To create a Python script file, save the Python code as a file with an extension of .py to identify it as a Python file. In the earlier labs in this lesson, the script hello.py was saved in this same way.

﻿

The next lab uses two Python script files, test1.py and test2.py, which are located in ~/python_scripts in the VM lin-hunt-cent. This is displayed below, in Figure 13.3-1:

﻿

﻿

Figure 13.3-1﻿

﻿

The script test1.py includes the functions reverse_text and main to output the following text when executed:

coding! are We World! Hello.
﻿

The script test2.py imports the function reverse_text from test1.py and supplies a different phrase to its own main function. This ability to import functions from other Python scripts allows code reuse from one script so that another script does not need to define a new function to produce the desired results. Executing test2.py outputs the following text:

phrase. different a is This 
﻿

Both of the scripts test1.py and test2.py contain a check for the value of a special variable formatted as __name__. The value of this variable changes according to how the script is executed. When a script is directly executed, the value of __name__ is __main__. If the script is executed as an import module, as displayed in test2.py, the value of this variable is the name of the imported module. This is why these two files output the following:

﻿

test1.py output﻿

coding! are We World! Hello
﻿

test2.py output﻿

You called a function from test1.py
You called a function from test2.py
phrase. different a is This
﻿

Referencing the variable __name__ allows the programmer to control Python script execution based on how the code is called. The print statements used in test1.py and test2.py are simple examples. The variable __name__ dynamically modifies code execution within a Python script, as highlighted in the following lab.

﻿

Create a Python Script
﻿

Create and call a function from within a Python script.

﻿

Workflow
﻿

1. Log into the VM lin-hunt-cent with the credentials below:

Username: trainee
Password: CyberTraining1!
﻿

2. Open Terminal.

﻿

3. Change the directory to the folder ~/python_scripts by entering the following command:

[trainee@lin-hunt-cent ~]$ cd python_scripts/
﻿

4. Open a new file named lab1.py in the text editor by entering the following command:

[trainee@lin-hunt-cent python_scripts]$ vim lab1.py
﻿

5. Set the text editor to Insert mode by entering the letter i﻿

﻿

6. Enter the following code to create a simple calculator function within the script:

def calc(op,num1,num2):
  if op == '+':
    return num1 + num2
  elif op == '-':
    return num1 - num2
  elif op == '*':
    return num1 * num2
  else:
    return "ERROR: Cannot compute."

def main():
  print("4 + 5 = ",str(calc('+',4,5)))
  print("4 - 5 = ",str(calc('-',4,5)))
  print("4 * 5 = ",str(calc('*',4,5)))
  print("4 / 5 = ",str(calc('/',4,5)))

if __name__ == "__main__":
  main()
else:
  print("You called a function from lab1.py")
﻿

NOTE: If copy-pasting the code in step 6 into the range, ensure that extra characters or additional tabbing are not passed into the text editor to avoid errors when executing the script in Step 9. Additionally, the underscores in the last section of the code (if __name__) are actually double underscores.
﻿

﻿

7. Exit the text editor's Insert mode by entering ESC.

﻿

8. Save the contents of the file lab1.py and exit the text editor by entering the following command:

:wq
﻿

9. Execute the Python script by entering the following command:

python lab1.py
﻿

10. Examine the results and analyze how different arguments in the function calls affected the script output. Notice how the division argument returns ERROR: Cannot compute. as this was not added to the function. 

﻿

11. Open the file test1.py within the text editor and add the following line of code to the very beginning:

from lab1 import calc
﻿

12. Add the following line of code to the function main(), within the same file:

print("9 * 42 = ",str(calc('*',9,42)))
﻿

This line of code includes a call to the function calc(), as found in lab1.py. The import statement above allows this function to be called, even though it is defined in a separate file.

﻿

13. Execute the modified test1.py and examine the results. 

﻿

The function calc from lab1.py performs the calculation as expected when  imported  and  called b y test1.py. The manner of execution is observed by lab1.py, which results in an additional print statement. Use the information from thi s lab to  answ er the n ext s eries of  questions.



Class Layout and Characteristics
The previous Python code examples in this lesson used variables and methods to manipulate data and program output. Another valuable tool is the Python class, which can be thought of as a mold for creating objects. Just as a mold shapes various types of materials, a single Python class can create various objects that share common attributes. 

﻿

The following lines of code illustrate the usefulness of Python classes. The first line defines the class without using the keyword def. This is followed by an object constructor __init__, which initializes a newly created object state. Since this Python class is concerned with malware, assume that each object of this class is a certain kind of malware (virus, trojan, worm, etc.) and the instance variables help define the object in relation to the class.

﻿

class Malware:

  # Constructor
  def __init__(self,name,mtype,tlevel)

    # Instance variables
    self.name = name
    self.mtype = mtype
    self.tlevel = tlevel

  # Class attributes
  attr1 = "has a malware signature"
  attr2 = "has been analyzed"

  # Class method
  def define(self):
    print(self.name, self.attr1)
    print(self.name, self.attr2)
    print("Refer to documentation for", self.name)
﻿

The instance variables are name, mtype (malware type), and tlevel (threat level). These instance variables have values provided as attributes to the constructor when a class object is instantiated, such as with the following line of code:

malware1 = Malware("Cryptolocker","trojan","high")
﻿

Instantiating an object in Python is similar to calling a method. The difference is that a class creates an object and assigns attributes to that object, while a method simply performs some action. In addition to instance variables that are specific to certain objects, there are also class attributes that are shared by each object of a class. In the example above, each object that is a member of the class Malware shares two attributes, regardless of the values of the instance variables.

﻿

Finally, classes may also contain their own methods. Defining a method within a class benefits from the parameter self, which is a reference to a particular object instance. For example, malwa re1 in th e code above is a variab le which  holds a Malware class object with the name Cryptolocker . The me thod define within the class Malware only needs to take in the parameter self, rather than a specific name value. This is because the name Cryptolocker is passed as an instance variable specific to the object malware1 and is referenceable as self.name when used in the class  method. ﻿

Create a Python Class
Create a class from within a Python script. Then, modify the script to alter class attributes.

﻿

Workflow
﻿

1. Open Terminal in the VM lin-hunt-cent.

﻿

2. Change directory into the folder ~/python_scripts by entering the following command:

[trainee@lin-hunt-cent ~]$ cd python_scripts/
﻿

3. Open the file lab2.py in the text editor by entering the following command:

[trainee@lin-hunt-cent python_scripts]$ vim lab2.py
﻿

4. Examine the Python code in this script. 

﻿

A class named APT is defined with a constructor which assigns several parameters to instance variables which will be unique for every APT class object. Next, several class variables are created with string values to be used in the class method define(). This method calls print statements which vary, depending on the instance variables and whether or not the argument malname is an empty string. The last several lines of code instantiate two objects of the class APT and call the method define() for each.

﻿

5. Exit the text editor by entering :q﻿

﻿

6. Execute the Python script by entering the following command:

python lab2.py
﻿

7. Examine the results, which are also provided below:

Lazarus has a MITRE ATT&CK ID of G0032
Lazarus is known to use the following malware: Wannacry
Wannacry has a MITRE ATT&CK ID of S0366
Lazarus affects the following operating system(s): Windows
Lazarus has a threat level of High

Wet Koala has a MITRE ATT&CK ID of WKRP
Wet Koala affects the following operating system(s): OSX
Wet Koala has a threat level of Low
﻿

An empty string value "" for malname is provided for aptY. This value altered the number of lines printed for the class object.

﻿

8. Open the text editor by entering the following command into the terminal:

vim lab2.py
﻿

9. Set the text editor to Insert mode by entering the letter i﻿

﻿

10. Edit the script lab2.py by adding the following after the last line of code:

aptY.attr3 = "is known to employ"
aptY.malname = "Phishing attacks"
aptY.malAttkID = "T1566"
aptY.define()
print("")
aptX.define()
﻿

11. Exit the text editor's Insert mode by entering ESC.

﻿

12. Save the contents of the file lab2.py and exit the text editor by entering the following command:

:wq
﻿

13. Execute the modified script lab2.py and examine the results.

﻿

Use the information from this lab to answer the next series of questions.

﻿






































































































































