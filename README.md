# AES_128-Cracker
Python tool to crack AES-128 encryption, upwards of 200,000 keys checked per second. Allows for variable of execution threads as well as several tweaks.

**EXEC_THREAD_SLEEP_TIME**   --> Time for producer threads to sleep<br>
**OUTPUT_SPY_SLEEP_TIME**    --> Time for consumer threads to sleep<br>
BUFFER_MEMORY_MULTIPLIER<br>
extra_consumers<br>

## Setup
First re-compile utils.pyx using "python setup.py build_ext --inplace". Afterward the main module, aes_cracker.py, can be run using "python aes_cracker.py"

## Command-Line Interface
![Alt text](https://github.com/bfaure/AES_128-Cracker/blob/master/resources/screenshot.png)

## Requirements
Python 2.7, PyCrypto, Cython


