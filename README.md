## Information
This is a website that allows users to upload a text file and generates a simple report using
information provided by querying VirusTotal's public API for the scan report of the file.




## Prerequisites
You need to install python and have git set up.




## How to use it
### Install
step1: create a folder that you want to hold the git repository

step2: do git clone
       ``git@github.com:EstelleWu/FileScanner.git``



### Use the application
### Launch
method1: open a command line in the local git repository, and run:
         ``python main.py``

method2: open the project using an editor (for example, PyCharm), run ``main.py``         


### Scan file
Go to [local host](http://localhost:8888/), use ``Choose File`` buttom to choose a file and then use ``Submit`` buttom to submit.
A table with hash_value (MD5 or Sha256), Fortinet detection name, Number of engines detected, Scan Date will show up, and in this page,
you can use ``Back`` buttom to go back to previous page.

Note: if nothing is detected , the cell for "Fortinet detection name" would be empty and the cell for "Number of engines detected" would be 0.




## Some details about the project
### Code layout
The ``main.py`` and ``parser.py`` contain the main logic, ``file_upload.html`` and ``report.html`` are the webpages



### Technology stack    
Python, Linux, Tornado
    


### Screenshots
![image](https://gitlab.com/estelle_wu/fortinet_test/uploads/6c9d644807e0e9cb1c9c654224f8220e/upload_page.jpg)
![image](https://gitlab.com/estelle_wu/fortinet_test/uploads/71c587dbabd03907bb99385d0a4c9449/report_page.jpg)



