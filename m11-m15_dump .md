
Set Up a Jupyter Notebook Using Python
Jupyter Notebook is a browser-based, open-source application that supports program development in a large number of programming languages. The development environment is known as a “notebook.” A Jupyter notebook provides an interactive programming session similar to a Command-Line Interface (CLI). Each notebook of code can be saved, then imported into and exported out of other existing notebooks or Python scripts. Jupyter's seamless integration allows for ease of use, code reusability, and code sharing.

﻿

Jupyter Notebook is useful for collaboration within a coding project as multiple users can use the same notebook to share code. However, Jupyter does not generate code nor does it translate code from one programming language to another. Jupyter cannot help with converting Java or C++ code into Python. This lesson focuses on using only the Python coding language within Jupyter Notebook.

﻿

The following lab walks through the process of creating a new Jupyter Notebook for the controlled execution of Python code. The lab highlights how portions of Python code can be separated into individual sections. This is similar to code breakpoints that allow debugging and analysis before executing an entire program.

﻿

Set Up a Jupyter Notebook
﻿

Create a new Jupyter Notebook. Then, test the notebook by entering Python code, executing commands, and examining the output of running sections of code.

﻿

Workflow
﻿

1. Log in to the VM lin-hunt-cent with the following credentials:

Username: trainee
Password: CyberTraining1!
﻿

2. Open Jupyter Notebook by selecting the Jupyter icon in the dock, as highlighted below in Figure 13.4-1:

﻿

﻿

Figure 13.4-1

﻿

Another option is to enter Jupyter into the system search bar. In either case, the application opens in a new browser window. 

﻿

3. Open a new notebook by selecting New under the tab Files, then Python 3 in the menu, as displayed in Figure 13.4-2, below:

﻿

﻿

Figure 13.4-2

﻿

This opens a new browser tab with a blank Jupyter Notebook. 

﻿

4. Define and print the function make_sandwich by entering the following code into the first cell:

def make_sandwich(meat,cheese,veg1,veg2):
	order = [meat,cheese,veg1,veg2]
	print(order)
make_sandwich("ham","cheddar","lettuce","tomato")
﻿

5. Select Run from the toolbar at the top of the page and observe the results.

﻿

The function make_sandwich accepts several string arguments, adds these arguments to a list, and prints the contents of the list. The following is the output after running the function:

['ham', 'cheddar', 'lettuce', 'tomato']
﻿

6. Enter the following code into the next empty cell:

make_sandwich("turkey","swiss","pickle","onion")
﻿

7. Run the new code to view its output.

﻿

The output is as follows:

["turkey","swiss","pickle","onion"]
﻿

8. Save this notebook with the new name Lab1.

﻿

9. Close the current tab for Lab1 to return to the original Jupyter tab and ensure the newly created notebook Lab1 is listed in the files directory.

﻿

10. Select Quit at the top right to exit the Jupyter interface, as highlighted in Figure 13.4-3, below:

﻿

﻿

Figure 13.4-3

﻿

11. Shut down the server.

﻿

Use the skills from this lab to answer the next question.

Click "Finish" to exit the event.
Auto-Advance on Correct

Use Python Modules in Jupyter
Programming code in blocks allows for easier reuse and implementation in Python. Script files protect these code blocks from the volatility of the Python interpreter CLI. Script files can also be modified to contain function and variable definitions for other Python scripts to use. These types of script files are referred to as "modules". 

﻿

In general, a module is not meant to execute as a stand-alone script. Instead, the standard practice is to use modules in other scripts through an import process. A module can be imported into other modules or scripts for execution without needing to redefine pre-existing functions. 

﻿

Modify a Python Module
﻿

Modify a Python script in Jupyter Notebook to use as a Python module. Use Jupyter to move the module to a different file path for easier access in the next lab. 

﻿

Workflow
﻿

1. Log in to the VM lin-hunt-cent with the credentials below:

Username: trainee
Password: CyberTraining1!
﻿

2. Open Jupyter Notebook.

﻿

3. Select the file Lab1.ipynb to open Lab1 in a new tab.

﻿

4. Remove the function call make_sandwich from the first cell by removing the following last line of the cell:

make_sandwich("ham","cheddar","lettuce","tomato")
﻿

5. Select the second cell containing the following code:

make_sandwich("turkey","swiss","pickle","onion")
﻿

6. Cut the second cell by selecting the scissors from the toolbar, as highlighted in Figure 13.4-4, below:

﻿

﻿

Figure 13.4-4

﻿

Removing the function calls from the file Lab1.py leaves only the definition for the function make_sandwich. The rest of this lab refers to this edited version of the file Lab1.py as a module.

﻿

7. Save the notebook as a Python script by selecting File, Download as, then Python (.py) from the menu toolbar.

﻿

8. Save the file by selecting Save File > OK in the resulting pop-up window.

﻿

Step 8 saves the file in the folder Downloads. For ease of use, follow the next set of steps to use Jupyter Notebook to move the file to the home folder of the trainee account. 

﻿

9. In Jupyter Notebook, select the tab Home, then select the directory Downloads from the tab Files, as highlighted in Figure 13.4-5, below:

﻿

﻿

Figure 13.4-5

﻿

10. After opening Downloads, select the box next to Lab1.py, then select Move from the toolbar under the tab Files.

﻿

Selecting Move displays the pop-up window Move an Item. The window requests a destination to move the selected file to. Jupyter defaults to the /home/trainee file path and then provides a text box to enter a more specific path within this directory.

﻿

11. Move the file to the trainee home directory by deleting any text in the file path text box, then selecting Move.

﻿

12. Return to the Jupyter Notebook home page by selecting either the blue folder under the tab Files or the browser's back arrow.

﻿

Import a Python Module
﻿

Use Jupyter Notebook to import a Python module into a new Python script or notebook. Continue working in Jupyter Notebook, in the VM lin-hunt-cent.

﻿

Workflow
﻿

1. From the Jupyter Notebook home page, open a new browser tab with a blank notebook by using the options under the tab Files.

﻿

2. Import the function make_sandwich by entering the following code in the first cell:

from Lab1 import make_sandwich
﻿

This line of code imports the function make_sandwich into the current Python script (or notebook, in this case) from the existing Python module Lab1. 

﻿

3. Execute the code to check for any errors associated with importing by selecting the line of code, then selecting Run from the toolbar at the top. 

﻿

There are no errors in this line of code. Jupyter indicates this by creating an empty new cell without any other output. The import line does not have any errors because the file Lab1.py exists in the same directory as the current notebook.

﻿

4. Enter the following line of code into the empty cell:

make_sandwich("roast beef","provolone","mushroom","bell pepper")
﻿

5. Execute the code by selecting Run and observe the imported function make_sandwich successfully execute the arguments provided in the current notebook, as displayed in Figure 13.4-6, below:

﻿

﻿

Figure 13.4-6

﻿

6. Quit the Jupyter Notebook server.

Click "Finish" to exit the event.
Auto-Advance



Python Library Modules
Python provides a number of pre-built modules for common tasks to aid in program efficiency. These modules are part of the Python standard library. Locating modules and their source code provides more information on the functionality of the different modules available. This information helps identify and select specific functions to import. This section reviews the following topics to enable analysts to leverage Python modules:

Python standard library
Identifying module functions
Locating a Python module
Python Standard Library
﻿

Although creating and importing custom modules are powerful for code reuse, it is not efficient to create a large number of modules to complete simple tasks such as the following:

Calculating math 
Enumerating filesystem paths
Determining the current date and time
The better option is to use the Python standard library. The library uses Python installers to provide built-in modules that provide standardized functions. For example, one common function from the standard library is math. When imported into a Python script, this function provides several methods of performing arithmetic such as trigonometric functions.

﻿

Another function from the standard library is print. This function prints objects to either a file or standard output (terminal). Unlike math, it is unnecessary to use an import statement to call print since it is a built-in function. Built-in functions are members of the standard library provided to all Python programs by default.

﻿

In addition to modules, the standard library also provides data types such as int, float, str, and list. This provides a great deal of core functionality for Python scripts and handles the logic necessary to ensure that these data types work as expected.

﻿

Identifying Module Functions
﻿

The previous lab used the following line of code to import a function:

from Lab1 import make_sandwich
﻿

This explicitly imports only the function make_sandwich from the module Lab1. Alternatively, the entire module can be imported so that the import includes all additional modules and their functions. This task uses the following syntax, replacing Lab1 with the specific module name:

import Lab1
﻿

Importing a module and all its functions requires Python to place each imported function into memory during execution. This may cause a Python script to use more resources than necessary. This is why the best practice is to import only those functions that are necessary to properly execute a specific Python script.

﻿

 Using dir()
﻿

The function dir() is a handy tool that returns a list of object attributes. It is a member of the standard library, so it does not need to be imported. Using dir() with a module returns the names of the module attributes and functions. Figure 13.4-7, below, displays how the function make_sandwich is listed at the end of all the attributes for the module Lab1.

﻿

﻿

Figure 13.4-7

﻿

The output for dir() depends on the nature of the module being analyzed. The module Lab1 contains only a single function, so its output is sparse. The standard library module math contains a number of functions associated with mathematics, so it outputs significantly more attributes, as displayed in Figure 13.4-8, below:

﻿

﻿

Figure 13.4-8

﻿

Outputting all available attributes is helpful when trying to recall the names of specific functions to import, so that the entire module does not need to be imported. As an example, a script may require computing the square root of a number. Performing the command dir(math) provides the function sqrt as an option. After identifying this function name, the following code can be used to import only the necessary function:

from math import sqrt
﻿

This minimizes the footprint of the script. 

﻿

Locating a Python Module
﻿

Locating Python modules and their source codes is helpful for editing a module's functionality and debugging. An example of a debugging case is if a custom Python program is designed to request the value of pi to 20 decimal places, but this always results in an error. The function pi belongs to the module math. Locating and analyzing the source code for math provides more information as to why this error always occurs. In Python, the function pi within the module math returns the value of pi to 15 decimal places (3.141592653589793) by default. Therefore, requesting a greater number of decimal places outputs an error. Reviewing the source code for different modules, such as math, helps understand their applications and limitations.

﻿

Using inspect
﻿

The location of a module depends on the organizational structure of a given Python project and whether a certain module is a member of the standard library. One way to locate a Python module is with the module inspect. Although inspect is a built-in module, it is not a member of the standard library. This module provides the method getfile(), which returns the path of the object being inspected. Figure 13.4-9, below, provides an example of importing inspect and printing the getfile() search for the function make_sandwich:

﻿

﻿

Figure 13.4-9

﻿

The method getfile() can also be used to identify the locations of modules. In the following example in Figure 13.4-10, the module inspect is calling upon itself to identify its own directory:

﻿

﻿

Figure 13.4-10

﻿

Use the information from this lab to answer the following questions.

Query Data from Elasticsearch
The following lab provides a real-world example of using Jupyter Notebook and Python for data analysis.

﻿

Query Data from Elasticsearch
﻿

Create a Jupyter Notebook that imports Python modules to query data from Elasticsearch.

﻿

Workflow
﻿

1. Log in to the VM lin-hunt-cent with the credentials below:

Username: trainee
Password: CyberTraining1!
﻿

2. Open a new notebook in Jupyter Notebook.

﻿

3. Import the functions Elasticsearch and Search from their respective modules by entering the following code in the first cell of the new notebook:

from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
﻿

These statements use the importing syntax from earlier in this lesson. Elasticsearch is a search engine that integrates with other software. Elasticseach_DSL is a high-level library that aids in performing searches with Elasticsearch.

﻿

4. Import the data manipulation tool pandas by entering the following command on the next line of the first cell:

import pandas as pd
﻿

This syntax includes an alias. Pandas is a popular Python tool for manipulating data and is commonly imported as pd. Aliases are useful shorthand, but not necessary.

﻿

5. Execute this line by selecting Run from the toolbar at the top and view any errors that may occur as a result of this code. 

﻿

6. Establish the identity of the Elasticsearch server with which this script communicates and define how communication occurs by entering the following code into the new blank cell:

es = Elasticsearch(['https://199.63.64.92:9200'],
ca_certs=False,verify_certs=False, http_auth=('jupyter','CyberTraining1!'))
searchContext = Search(using=es, index='*:so-*', doc_type='doc')
﻿

7. Execute this code by selecting Run and read the warning.

﻿

The notebook displays the warning because the connection with the Elasticsearch server is not fully secure. The next step disables this warning for the purposes of this lab.

﻿

8. Import a module that disables warnings from the previous block of code by entering and executing the following lines in the new blank cell:

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
﻿

9. Assign an object a search query with arguments defining what to search for by entering and executing the code below in the new blank cell:

s = searchContext.query('query_string', query='event.module:sysmon AND event.dataset:process_access')
﻿

10. Perform the search and check whether it is successful by entering and executing the following final block of code in the new blank cell:

response = s.execute()
if response.success():
  df = pd.DataFrame((d.to_dict() for d in s.scan()))
df
﻿

NOTE: Avoid errors from copy-pasting code by verifying the code indentation is correct.

﻿

A successful search outputs the search results to a two-dimensional data frame. A data frame is a table containing the results of the Elasticsearch query. This output can either be manipulated directly with additional code in subsequent blocks or saved to a new file for analysis at a later date.

﻿

11. Save this notebook with the new name Lab2.

﻿

12. Create a copy of this notebook by selecting File > Make a Copy. 

﻿

This opens a new browser tab with a new notebook named Lab2-Copy1. 

﻿

13. Save the notebook Lab2-Copy1 as Lab 3 for later use.

﻿

Use the information from this lab to answer the following question.

Click "Finish" to exit the event.
Auto-Advance on Correct

Data Parsing and Filtering with Python Modules and Functions
The Elasticsearch query from the previous lab outputs many columns of data. This includes the column observer, as highlighted in Figure 13.4-11, below. This column provides Fully Qualified Domain Names (FQDN) as part of strings formatted as {'name': 'FQDN'}. It's possible to parse a list of system FQDNs from these query results after filtering the FQDN from the rest of the characters in the column values.

﻿

﻿

Figure 13.4-11

﻿

Parse and Filter Data
﻿

Parse and filter data from the Elasticsearch query results in the Lab2 Jupyter Notebook. 

﻿

Workflow
﻿

1. Log in to the VM lin-hunt-cent with the credentials below:

Username: trainee
Password: CyberTraining1!
﻿

2. Open the notebook Lab2 in Jupyter Notebook.

﻿

3. Perform text manipulation to extract the FQDNs from the column observer and create a new column systems by entering and executing the following code to the empty cell at the bottom of the Lab2 notebook:

df['observer'] = df['observer'].astype(str)
df['systems'] = df['observer'].str.rsplit("'",3).str[2].str.strip()
df
﻿

The Pandas data frame method astype(str) casts the contents of the column observer as a string. Running this command creates the column systems and populates its values through string manipulation of the values in the column observer. The column observer formats its values as {'name': 'FQDN'}, which are two substrings in single quotes that are separated by a colon. This substring arrangement allows the function str.rsplit to use the single quote delimiter to split the string. 

﻿

The function str.rsplit("'",3) splits the string {'name': 'FQDN'} at each single quote before FQDN, which creates three substrings. Substrings are counted from zero, so the FQDN is included in substring number two. This is noted with .str[2]. The method str.strip() removes any leading or trailing whitespace characters.

﻿

Choosing different substring values changes the results. For example, the output would be different if str[2] was changed to str[0], as displayed in Figure 13.4-12, below. As str.rsplit("'",3) splits the entire string in each entry of the column observer into three substrings, str[0] selects the first substring. The first substring is always {'name.

﻿

﻿

Figure 13.4-12

﻿

4. Print the column systems of the Elasticsearch query results by entering and executing the following code into a new empty block in the notebook:

print(df['systems'])
﻿

The results present duplicate values. 

﻿

5. Filter by unique values by invoking the pandas function unique(), as follows:

print(df['systems'].unique())
﻿

Filtering reduces the number of FQDN values from 1240 to just 14 unique values. 

﻿

6. Sort the list of unique FQDNs by combining the function sorted() with the function unique(), as follows:

print(sorted(df['systems'].unique()))
﻿
Parsing and Filtering with Regular Expressions
The previous lab presented a method of parsing and filtering data that uses string manipulation with the functions rsplit() and strip(). Data can also be parsed and filtered using regular expressions, which act as a powerful shorthand for complex pattern matching. 

﻿

Regular expressions can be used with the Elasticsearch query results from Lab2. In this example, the column observer contains strings that include FQDNs with extraneous characters and information. Figure 13.4-13, below displays how head() is used to limit the number of lines that are printed from the data frame:

﻿

﻿

Figure 13.4-13

﻿

Each entry in this column follows the pattern {'name': '[FQDN]'}. To extract specific data from each row in the column, a regular expression can be used to parse the FQDN from the substring housed within the second set of single quotes as shown in the code block in Figure 13.4-14, below:

﻿

﻿

Figure 13.4-14

﻿

In this code block, the module for regular expressions (re) is imported, and the data within the column observer is cast into strings. Then, the data in each row of observer is inspected using the function re.findall(). This function is useful in this case since there are multiple pattern matches for each row. The following regular expression is used with this function:

r'\'(.+?)\''
﻿

This regular expression includes the following components:

r - Treats the pattern as a raw string that allows escape characters.
' - Opens the pattern (only the first single quote).
\' - Indicates that a single quote is part of the pattern and not a closing single quote ending the pattern.
(.+?) - Accepts any characters that follow the previous single quote in a non-greedy fashion. Without the question mark, the entire original string would be returned.
\' - Closes the second single quote pattern, which results in a pattern that searches for any characters contained by single quotes.
' - Closes the first single quote pattern and defines what the regular expression should search for.
The function re.findall() returns a list containing all pattern matches within a string. This is useful because each string has two regular expression pattern matches. For example, the first string results in ['name', 'dmz-smtp.energy.com]. Since it is clear that the second substring contains the FQDN, only fqdn[1] is printed in the code block from Figure 13.4-14, above.

﻿

The following additional regular expression parsing functions are also available:

re.match() - Searches for a regular expression pattern in a string and returns the first occurrence in the first line. Also ignores any additional patterns that exist in a multi-line string.
re.search() - Finds the first pattern match for every line in a string.
Parsing and filtering data allows analysts to reduce the size of a dataset and format it for further analysis. A common analysis task is to search data to match known strings or substrings. The systems data from the notebook Lab2 is an example of data that is ready for closer analysis since it was parsed and filtered in the last lab. This data provides strings and substrings to match against. 

﻿

Search Data with Regular Expressions
Continue working in the VM lin-hunt-cent. Identify indicators of compromise by using the regular expression module to search the Elasticsearch query results for the following systems:

BP-WKSTN-10.energy.lan
eng-wkstn-3.energy.lan
zeroday.energy.lan
Workflow
﻿
1. Open the notebook Lab2 in Jupyter Notebook, if it is not already open.

﻿

2. Search the Elasticsearch query results by entering and executing the following code in the free block at the end of the notebook:

import re
search_list = ["BP-WKSTN-10.energy.lan","eng-wkstn-3.energy.lan","zeroday.energy.lan"]

for i in df['systems'].unique():
    for j in search_list:
        if re.search(j,i):
            print("Found a match for " + j)
﻿

This output identifies two systems in the search_list that are present in the Elasticsearch query results, so they are worth investigating. This search calls the function unique() before engaging the column systems to provide refined results. Performing this search without unique() affects the number of results returned and includes the duplicate values that exist in the column systems.

﻿

The method above is useful when there is a list of known strings to search for, such as FQDNs. However, often there is only a substring available, such as wkstn. 

﻿

3. Display all systems containing the substring wkstn in their FQDN by entering and executing the following:

for i in df['systems'].unique():
    wkstn_hunt = re.search("wkstn", i)
    if wkstn_hunt:
        print("Discovered " + i)
﻿

The search result prints only the FQDNs that meet the criteria in the code. These results indicate that the search is case-sensitive. 

﻿

4. Ignore casing in the search results by adding re.IGNORECASE to the argument and executing the search, again, as follows:

for i in df['systems'].unique():
    wkstn_hunt = re.search("wkstn", i, re.IGNORECASE)
    if wkstn_hunt:
        print("Discovered " + i)
﻿

This results in the regular expression search and filtering provide the most accurate results, according to the search criteria.


Using Python Data Parsing Functions
Python Data Parsing
﻿

Parse and filter data from Elasticsearch query results.

﻿

Workflow
﻿

1. Log in to the VM lin-hunt-cent with the credentials below:

Username: trainee
Password: CyberTraining1!
﻿

2. Open the notebook Lab3 in Jupyter Notebook.

﻿

3. Ensure the notebook displays the correct Elasticsearch query results by running each block of code independently, starting from the top, and comparing them to the target output in Figure 13.4-15, below:

﻿

﻿

Figure 13.4-15

﻿

The column message in the Elasticsearch results displays less information than the data displayed in the output. This is because the data string is truncated to easily fit in the window at the expense of visibility.

﻿

4. Expand the truncated data string by entering and executing the following lines of code in the empty cell below the Elasticsearch query results:

pd.options.display.max_rows
pd.set_option('display.max_colwidth', None)

df['message'].head(1)
﻿

Figure 13.4-16, below, displays the data in this expanded string. The string starts with information such as a MITRE Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK®) technique Identifier (ID) and name. This may be valuable information for analysts to refer back to and output as an alert.

﻿

﻿

Figure 13.4-16

﻿

5. Parse the information from the first entry in message by entering and executing the following lines of code:

import re
df['message'] = df['message'].astype(str)

for i in df['message'].head(1):
    attkID = re.findall(r'technique\_id\=(.*?)\,', i)
    if attkID:
        attkName = re.findall(r'technique\_name\=(.*?)\n', i)
        print(attkID[0], attkName[0])
﻿

This outputs the following string:

T1055.001 Dynamic-link Library Injection.
﻿

These results are useful for displaying information about the detected technique. However, the full string in the message column does not reveal a system name.

﻿

6. Include data from the column observer by editing and executing the following code block:

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
﻿

This code block uses two different indexes. In the for loop, the index variable i contains a value from a string in the column message. This makes it safe to perform the regular expression logic against the value i. However, when the column observer is referenced, the value i cannot be used as an index because it is a string and not a reference to the row. Instead, this block of code uses a separate variable, index, which increases by one through each iteration of i. This allows the print statement to reference the correct system name. Figure 13.4-17, below, displays the output:

﻿

﻿

Figure 13.4-17

Click "Finish" to exit the event.
Auto-Advance on Correct














































