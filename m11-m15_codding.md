### CDAH-M13L1-Python Data Types and Program Flow

Here is a breakdown of all the Python code snippets found in the file [m11-m15_dump .md](https://github.com/lukasaq/hack-class/blob/main/m11-m15_dump%20.md), along with explanations of how each executes:

---

### 1. Print a String
```python
x = "America!"
print(x)
```
**What it does:**  
Assigns `"America!"` to the variable `x` and prints it.  
**Output:**  
America!

---

### 2. String Creation and Print
```python
output = str("Hello")
print(output)
```
**What it does:**  
Creates a string `"Hello"` using the `str()` constructor (unnecessary here, but valid), assigns it to `output`, and prints it.  
**Output:**  
Hello

---

### 3. Integer Creation and Print
```python
output = int(10)
print(output)
```
**What it does:**  
Creates an integer `10`, assigns it to `output`, and prints it.  
**Output:**  
10

---

### 4. Float Creation and Print
```python
output = float(10.1)
print(output)
```
**What it does:**  
Creates a float `10.1`, assigns it to `output`, and prints it.  
**Output:**  
10.1

---

### 5. Complex Number Creation and Print
```python
output = complex(10.j)
print(output)
```
**What it does:**  
Creates a complex number `10j`, assigns it to `output`, and prints it.  
**Output:**  
10j

---

### 6. List Creation and Print
```python
y = list(["apple", "orange", 10])
print(y)
```
**What it does:**  
Creates a list containing two strings and an integer, assigns it to `y`, and prints it.  
**Output:**  
['apple', 'orange', 10]

---

### 7. Tuple Creation and Print
```python
z = tuple(("apple", "orange", 10))
print(z)
```
**What it does:**  
Creates a tuple (immutable list) with two strings and an integer, assigns it to `z`, and prints it.  
**Output:**  
('apple', 'orange', 10)

---

### 8. Range and For Loop
```python
x = range(0,5,1)
for n in x:
    print(n)
```
**What it does:**  
Creates a range object from 0 to 4 (5 is excluded). The for loop iterates through the range and prints each number.  
**Output:**  
0  
1  
2  
3  
4  

---

### 9. Set Creation and Print
```python
x = set(["apple", "orange", 10])
print(x)
```
**What it does:**  
Creates a set (unordered, unique items) with two strings and an integer, assigns it to `x`, and prints it.  
**Output (order may vary):**  
{'apple', 10, 'orange'}

---

### 10. Frozenset Creation and Print
```python
x = frozenset({'apple', 'orange', 10})
print(x)
```
**What it does:**  
Creates an immutable set (frozenset) with the same elements and prints it.  
**Output (order may vary):**  
frozenset({10, 'apple', 'orange'})

---

### 11. Boolean Evaluation and Print
```python
x = 10
y = 11
z = bool(x > y)
print(z)
```
**What it does:**  
Compares x and y, checks if x > y (which is False), converts the result to a Boolean, assigns to `z`, and prints it.  
**Output:**  
False

---

### 12. Bytes Creation and Print
```python
x = bytes(10)
print(x)
```
**What it does:**  
Creates a bytes object of length 10 (all zero bytes), assigns to `x`, and prints it.  
**Output:**  
b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

---

### 13. Bytearray Creation and Print
```python
x = bytearray(10)
print(x)
```
**What it does:**  
Creates a mutable bytes array of length 10 (all zero bytes), assigns to `x`, and prints it.  
**Output:**  
bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

---

### 14. Memoryview Creation and Print
```python
x = memoryview(b"10")
print(x)
```
**What it does:**  
Creates a memoryview of the bytes object `b"10"`, assigns to `x`, and prints it.  
**Output:**  
<memory at 0x...> (shows the memory address)

---

### 15. Help Function
```python
help(print)
```
**What it does:**  
Prints the documentation for the built-in `print` function in Python.  
**Output:**  
Help text about `print`.

---

### 16. Input Example
```python
x = input('Enter your name:')
print('Hello, ' + x)
```
**What it does:**  
Prompts the user to enter their name, then prints a greeting using the entered value.  
**Sample Output:**  
Enter your name:  
User1  
Hello, User1

---

### 17. Arithmetic Operations
```python
1 + 1
```
**What it does:**  
Evaluates the expression (in interactive mode or script); outputs `2`.

```python
5 * (10 + 5)
```
**What it does:**  
Evaluates the expression (in interactive mode or script); outputs `75`.

---

### 18. Assign and Print Variable
```python
x = 5 * (10 + 5)
print(x)
```
**What it does:**  
Calculates the value, assigns it to `x`, and prints it.  
**Output:**  
75

---

### 19. String Assignment and Slicing
```python
y = "Hello, World!"
print(y[7:13])
z = (y[7:13])
```
**What it does:**  
- Assigns a string to `y`.
- Prints the substring from index 7 to 12 (Python excludes the end index), which is 'World!'.
- Assigns 'World!' to `z`.  
**Output:**  
World!

---

### 20. Code Block Example (Functions)
```python
def code1(): 
    x = 3 #same block
    y = x + 6 #same block
    print(y) #same block

def code2():
    x = 10 #new block
    y = x + 6 #new block
    print(y) #new block
```
**What it does:**  
Defines two functions.  
- `code1()` assigns 3 to x, 9 to y, and prints 9.  
- `code2()` assigns 10 to x, 16 to y, and prints 16.  
These functions do nothing until called.

---

### 21. Conditional Statement
```python
x = 10
y = 560
if x < y:
    print("x is less than y")
```
**What it does:**  
Checks if x is less than y (True), then prints a message.  
**Output:**  
x is less than y

---

### 22. Conditional with Else
```python
x = 10
y = 560
if x < y:
    print("x is less than y")
else:
    print("x is not less than y")
```
**What it does:**  
Checks if x is less than y (True), prints first message; else, would print the second.  
**Output:**  
x is less than y

---

### 23. For Loop with Variable Range
```python
x = 4
for i in range(0, x):
    print(i)
```
**What it does:**  
Prints numbers 0 through 3.  
**Output:**  
0  
1  
2  
3

---

### 24. While Loop Example
```python
x = 0
while (x < 3):
    print("Loop")
    x += 1
```
**What it does:**  
Prints "Loop" three times, incrementing x each time.  
**Output:**  
Loop  
Loop  
Loop

---

### 25. While Loop up to 5
```python
x = 0
while (x < 5):   
    print("Loop")
    x += 1
```
**What it does:**  
Prints "Loop" five times as x goes from 0 to 4.  
**Output:**  
Loop  
Loop  
Loop  
Loop  
Loop

---

### 26. If Statement with a and b
```python
a = 45
b = 21
if a > b:
    print("a is greater than b")
```
**What it does:**  
Checks if a is greater than b (True), prints the message.  
**Output:**  
a is greater than b

---

### 27. If/Else Boolean Logic Example
```python
if a < b:
    print("a is less than b")
else:
    print("a is not less than b")
```
**What it does:**  
Checks if a is less than b (False), so prints the else clause.  
**Output:**  
a is not less than b

---

### 28. For Loop 1 to x-1
```python
x = 7
for i in range(1, x):
    print(i)
```
**What it does:**  
Prints numbers 1 through 6.  
**Output:**  
1  
2  
3  
4  
5  
6

---

### 29. While Loop with Else
```python
counter = 0
while counter < 3:
    print("inside loop")
    counter += 1
else:
    print("outside loop")
```
**What it does:**  
Prints "inside loop" three times, then prints "outside loop" after the loop ends.  
**Output:**  
inside loop  
inside loop  
inside loop  
outside loop

---

### 30. Nested For Loops for Combinations
```python
users = ['user47', 'user71', 'user82', 'user93']
hosts = ['wks6', 'mailserver', 'kali2', 'centos3', 'ftp', 'www']
for x in users:
    for y in hosts:
        print(x, y)
```
**What it does:**  
Prints every possible combination of a user and a host.  
**Sample Output:**  
user47 wks6  
user47 mailserver  
... (up to 24 combinations)

---

If you want more details on any snippet or how to run them, let me know!

### CDAH-M13L2-Python Data Structures

Here is all the code extracted from the file m11-m15_dump .md, followed by detailed explanations for each code snippet:

---

### 1. Defining and Modifying a List

```python
numbers = [1, 2, 3, 4, 5]
numbers = [1, 2, 4, 5]
```
- Creates a list called numbers with values 1 through 5.
- The second line redefines the numbers list, effectively removing the number 3.

---

### 2. Looping Over a List with a For Loop

```python
numbers = [1, 2, 3, 4, 5]

for number in numbers:
    print(number)

#Output
1
2
3
4
5
```
- Iterates over each element in numbers and prints it to the console.

---

### 3. Looping Over a List with a While Loop

```python
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
```
- Defines a list numbers.
- Gets the length of a list (but mistakenly uses list instead of numbers).
- Uses a while loop to print each item by index.

**Note:** This code has a bug: length = len(list) and print(list[i]) should be length = len(numbers) and print(numbers[i]).

---

### 4. List Comprehension for Iteration

```python
numbers = [1, 2, 3, 4, 5]
[print(number) for number in numbers] 

#Output
1
2
3
4
5
[None, None, None, None, None]
```
- Uses a list comprehension to print each number.
- The list comprehension returns a list of Nones because print() returns None.

---

### 5. Creating and Unpacking Tuples

```python
tuple_1 = ("blue", "green", "yellow", 10)

info = ("Kathy Simpson", "Marketing", "Senior")
(name, department, level) = info

print(name)
print(department)
print(level)

#Output
Kathy Simpson
Marketing
Senior 
```
- tuple_1 is a tuple with mixed data types.
- info is unpacked into three variables: name, department, and level, which are then printed.

---

### 6. Dictionary Creation and Iteration

```python
dictionary = {
    key: value,
    key: value,
    key: value
}

dict = {'name': 'Jeff', 'age': '25', 'address': 'New York'}
items = dict.items()
print(items)
dict_items([('name', 'Jeff'), ('age', '25'), ('address', 'New York')])

#Output
dict_items([('name', 'Jeff'), ('age', '25'), ('address', 'New York')])
```
- Shows dictionary creation (the first block is pseudocode).
- The second block creates a real dictionary and prints its items.

---

### 7. Iterating Over Dictionary Keys and Values

```python
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
```
- Extracts and prints only the keys or only the values from a dictionary.

---

### 8. Set Creation

```python
set_a = {"item 1", "item 2", "item 3",}
```
- Creates a set of unique items.

---

### 9. Creating Multidimensional Lists (Arrays)

```python
List = [[1, 2], [3, 4], [5, 6]]
array = [[1, 2, 3, 4], [5, 6, 7, 8]]

#Output
print(array)
[[1, 2, 3, 4], [5, 6, 7, 8]]
print(type(array))
<class 'list'>
```
- List and array are lists of lists (2D arrays).
- Printing array shows its structure; type(array) returns <class 'list'>.

---

### 10. Building Arrays from Rows

```python
row1 = [0, 0, 0, 0, 0]
row2 = [0, 0, 0, 0, 0]
row3 = [0, 0, 0, 0, 0]

array = [row1, row2, row3]

for row in array:
    print (row)
```
- Defines each row as a list, then groups them into a 2D array.
- Loops over each row and prints it.

---

### 11. Creating an Empty Array

```python
array = []
print(array)
```
- Creates and prints an empty list.

---

### 12. Creating Lists and Grouping into an Array

```python
List = [1, 2, 3, 4]
List1 = [5, 6, 7, 8]
List2 = [9, 10, 11, 12]

array = [List, List1, List2]

for list in array:
    print(list)

for list in array:
    print(List2)
```
- Creates three lists and groups them into a list of lists.
- First for-loop prints each list.
- Second for-loop prints List2 for each iteration (so three times).

---

### 13. Creating Rows and a New Array

```python
row1 = [0, 0, 0, 0]
row2 = [0, 0, 0, 0]
row3 = [0, 0, 0, 0]

array1 = [row1, row2, row3]

for row in array1:
    print (row)
```
- Similar to earlier: defines rows, groups into array1, and prints each row.

---

### 14. Creating and Printing an Empty Dictionary

```python
new_dictionary = {}
print(new_dictionary)
print(type(new_dictionary))
```
- Creates an empty dictionary.
- Prints the dictionary and its type.

---

### 15. Creating and Iterating Over a Dictionary

```python
test_results = {"Frank":"Passed", "Corey":"Passed", "Daniel":"Failed"}

for results in test_results.values():
    print(results)
```
- Creates a dictionary of test results.
- Prints only the values ("Passed", "Passed", "Failed").

---

### 16. Adding an Item to a Dictionary and Printing

```python
test_results["Alexandra"] = "Failed" 
print(test_results)
```
- Adds a new key:value pair to the dictionary and prints the updated dictionary.

---

### 17. Creating and Printing Lists

```python
groceries = ["apples", "milk", "chicken", "bread"]
prices = ["2.99", "3.60", "10.99", "3.10"]

print(groceries)
print(prices)
```
- Defines two lists and prints them.

---

### 18. Appending to a List and Iterating

```python
groceries.append("oranges")

for number in groceries:
    print(number)
```
- Adds "oranges" to the groceries list.
- Prints each item in groceries.

---

### 19. Combining Dictionaries and Lists

```python
employees = {}

employees["Name"] = ["Chuck", "Emily", "Max", "Laura"]
employees["Age"] = ["35", "25", "42", "55"]

print(employees)

new_employees = ['Sam', 'Frank', 'Amy']

employees["Name"].append(new_employees)

print(employees)
```
- Creates a dictionary employees with two keys, each holding a list.
- Adds a new list new_employees as a sublist to employees["Name"].
- Prints the dictionary before and after appending.

---

## Execution Explanations

- All code snippets are for basic Python data structures: lists, tuples, dictionaries, and sets.
- The code demonstrates creation, iteration, modification, and nested data structures.
- Most code can be run as-is in a Python interpreter to see the results.
- Errors: The while loop in section 3 has a variable name bug; change list to numbers.
- The multidimensional lists demonstrate how to group lists into a list of lists (like a 2D array).
- The dictionary/list combination in the last section shows that dictionaries can have lists as values, and you can append new lists to those values.

If you need code for a specific section explained in more depth or want to see the output of any snippet, let me know!

### CDAH-M13L3-Python Functions and Classes

Certainly! Below, I’ve extracted all the Python code examples from the provided markdown and explained how each one executes, step by step. Each code block is followed by a clear explanation.

---

### 1. Basic Function Definition and Execution

```python
def print_text():
  print("Hello World!")

print_text()
```
**How it executes:**
- Defines a function called print_text that prints "Hello World!".
- The function is then called with print_text(), so "Hello World!" is displayed when the script runs.

---

### 2. Function with a Parameter

```python
def print_text(msg):
  print(msg)
```
**How it executes:**
- Defines print_text with a parameter msg.
- When called, it will print whatever argument is passed as msg.
- If you call print_text("Hi!"), it will print "Hi!".

---

### 3. Function Call Without Required Argument (Error Example)

```python
def print_text(msg):
  print(msg)

print_text()
```
**How it executes:**
- Attempts to call print_text without the required msg argument.
- Results in a TypeError: print_text() missing 1 required positional argument: 'msg'.

---

### 4. Passing a Variable as an Argument

```python
myMsg = "Hello World!"
print_text(myMsg)
```
**How it executes:**
- Sets myMsg to "Hello World!".
- Calls print_text(myMsg), which prints "Hello World!".

---

### 5. Function with Multiple Parameters

```python
def new_print_text(string1, string2):
  print(string1, string2)

myMsg1 = "Hello "
myMsg2 = "World!"

new_print_text(myMsg1, myMsg2)
```
**How it executes:**
- Defines new_print_text to accept two parameters.
- Sets myMsg1 and myMsg2, then calls the function.
- Prints "Hello  World!" (including the space after Hello).

---

### 6. Keyword Arguments

```python
myMsg1 = "Hello "
myMsg2 = "World!"

new_print_text(string2=myMsg2, string1=myMsg1)
```
**How it executes:**
- Calls new_print_text with arguments explicitly named.
- Order doesn’t matter due to the use of keywords.
- Prints "Hello  World!".

---

### 7. Function with a Default Parameter

```python
def new_print_text(string2, string1="This Is My"):
  print(string1, string2)
```
**How it executes:**
- If string1 isn’t provided when calling, it defaults to "This Is My".
- Calling new_print_text("World!") prints "This Is My World!".

---

### 8. Variable Number of Arguments (*args)

```python
def variable_print_text(*args):
  for i in args:
    print(i)

variable_print_text("Hello","World!","We","are","coding!")
```
**How it executes:**
- *args allows passing any number of arguments.
- Each argument is printed on a new line:
  ```
  Hello
  World!
  We
  are
  coding!
  ```

---

### 9. Returning Values & Reversing Input

```python
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
```
**How it executes:**
- reverse_text reverses the order of the input arguments and concatenates them into a string.
- The result is: " coding! are We World! Hello" (note leading space).
- The string is printed.

---

### 10. Calculator Function & Script Execution

```python
def calc(op, num1, num2):
  if op == '+':
    return num1 + num2
  elif op == '-':
    return num1 - num2
  elif op == '*':
    return num1 * num2
  else:
    return "ERROR: Cannot compute."

def main():
  print("4 + 5 = ", str(calc('+', 4, 5)))
  print("4 - 5 = ", str(calc('-', 4, 5)))
  print("4 * 5 = ", str(calc('*', 4, 5)))
  print("4 / 5 = ", str(calc('/', 4, 5)))

if __name__ == "__main__":
  main()
else:
  print("You called a function from lab1.py")
```
**How it executes:**
- calc performs basic arithmetic based on the op argument.
- main demonstrates usage with sample operations.
- If the script is run directly, the results of each operation are printed.
- If imported, "You called a function from lab1.py" is printed instead.

---

### 11. Importing and Using Functions Across Files

```python
from lab1 import calc

def main():
  # ...other code...
  print("9 * 42 = ", str(calc('*', 9, 42)))
```
**How it executes:**
- Imports the calc function from lab1.py.
- main uses calc to compute 9 * 42 and prints the result.

---

### 12. Python Class Example

```python
class Malware:

  # Constructor
  def __init__(self, name, mtype, tlevel):
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

malware1 = Malware("Cryptolocker", "trojan", "high")
malware1.define()
```
**How it executes:**
- Defines a class Malware with attributes and a method.
- Instantiates malware1 with specific values.
- Calls define(), which prints information about malware1.

---

### 13. Editing and Using Class Attributes

```python
aptY.attr3 = "is known to employ"
aptY.malname = "Phishing attacks"
aptY.malAttkID = "T1566"
aptY.define()
print("")
aptX.define()
```
**How it executes:**
- Sets or modifies attributes on aptY object.
- Calls its define() method, prints information (depends on how define() is implemented).
- Prints a blank line.
- Calls define() on another instance, aptX.

---

## Summary Table

| Code Block # | Concept                      | Main Action                                                     |
|--------------|------------------------------|-----------------------------------------------------------------|
| 1            | Basic Function               | Prints "Hello World!"                                           |
| 2            | Function Parameter           | Prints whatever argument is passed                              |
| 3            | Error Example                | Shows error when parameter is missing                           |
| 4            | Argument Passing             | Prints variable value                                           |
| 5            | Multiple Parameters          | Prints two strings                                              |
| 6            | Keyword Arguments            | Arguments assigned by name                                      |
| 7            | Default Parameter            | Uses a default value if not provided                            |
| 8            | *args                        | Prints variable number of arguments                             |
| 9            | Return Value                 | Reverses and concatenates input, prints result                  |
| 10           | Calculator Function          | Performs and prints results of arithmetic operations            |
| 11           | Importing Functions          | Uses functions from another file                                |
| 12           | Class Example                | Defines class, instantiates object, prints info                 |
| 13           | Class Attribute Modification | Modifies and prints updated class attributes                    |

---

If you would like further breakdown or want to see any code block in action, let me know!


