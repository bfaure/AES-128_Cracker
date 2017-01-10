from __future__ import print_function
import os

from Crypto.Cipher import AES

src_dir 			= "Computer Project 1/"
key_length 			= 32 # Length of key in hex digits
max_keys_in_list 	= 5000000 # Max length of key list sent back to producer

# Prints the contents and lengths of all project files.
def file_stats():

	print ("\n")

	files = os.listdir(src_dir)
	
	for filename in files:

		if filename in ["README.txt",".DS_Store"]:
			continue

		short_filename = filename
		filename = src_dir+filename
		cur_file = open(filename, 'rb')

		line = cur_file.readline()

		print (short_filename+"   text: "+line)
		print (short_filename+" length: "+str(len(line))+"\n")


# Ensures that the Crypto.Cipher.AES module is functioning properly by 
# comparing the string in Textplaintext.txt to the output of decrypting
# the string in Testciphertext.txt (using key found in Textkey.txt)
def validate():

	ciphertext_file = open(src_dir+"Testciphertext.txt", 'rb')
	ciphertext 		= ciphertext_file.readline()

	plaintext_file 	= open(src_dir+"Testplaintext.txt", 'rb')
	plaintext 		= plaintext_file.readline()

	key_file 		= open(src_dir+"Testkey.txt", 'rb')
	key 			= key_file.readline()

	cipher_binary 	= ciphertext.decode("Hex")
	key_binary 		= key.decode("Hex")
	
	calculated_plaintext = decrypt(cipher_binary, key_binary)
	calculated_plaintext = calculated_plaintext[:len(plaintext)]

	if calculated_plaintext != plaintext:
		print ("\n**Cypto.Cipher.AES did not return correct values!")
		print ("Original plaintext    = ["+plaintext+"]")
		print ("Calculated plaintext  = ["+calculated_plaintext+"]\n")
		return False

	else:
		print ("\n*Crypto.Cipher.AES functioning properly.\n")
		return True


# Class to hold possible keys and their corresponding plaintext outputs
class test_result:

	def __init__(self, plaintext, key, key_clean):
		self.found_plaintext = plaintext
		self.key_used = key 
		self.key_nice = key_clean

	def write_to_file(self, file_handle):
		string_representation = "{plaintext:"+str(self.found_plaintext)+"},{key:"+str(self.key_used)+"},{key_num:"+str(self.key_nice)+"}\n"
		file_handle.write(string_representation)

# Class to manage user interaction with the key.
class key_t:

	def __init__(self, filename,thread_num=0,start_search=None,end_search=None):

		self.src_file 		= filename
		src_file 			= open(filename, 'rb')
		self.text 			= src_file.readline()

		self.cur_appendage_value 	= 0
		self.appendage_length 		= 32-len(self.text)
		self.max_appendage_value	= (16 ** self.appendage_length)-1
		self.keyspace 				= (16 ** self.appendage_length)-1
		self.thread_num				= thread_num

		# If we are multithreading we need to adjust the search range
		if thread_num!=None and start_search!=None and end_search!=None:
			self.cur_appendage_value = start_search
			self.max_appendage_value = end_search

	# Returns the max number of different keys we could test with this IV
	def get_keyspace(self):
		return self.max_appendage_value

	# Returns a list of keys of length n, if n is not set it will return all
	# keys in this keyspace
	def get_keys(self,n=-1):

		if n == -1:
			n = self.max_appendage_value - self.cur_appendage_value

		over_max = False

		if n >= max_keys_in_list:
			n = max_keys_in_list
			over_max = True


		keys = []

		i=0
		while(i<n):
			
			key,key_clean = self.get_key()

			keys.append([key,key_clean])
			
			if key==-1:
				break

			i+=1

		if over_max:
			if keys[len(keys)-1][0]!=-1:
				keys.append([-2,-2])

		return keys

	# Returns a possible key then increments the appendage value such
	# that the next time this is called the returned key will be increased
	# by one.
	def get_key(self):

		if self.cur_appendage_value >= self.max_appendage_value:

			#print ("\nThread "+str(self.thread_num)+" seached its entire keyspace for "+self.src_file)
			return -1,-1

		try:
			base 		= hex(self.cur_appendage_value)[2:]
		except:
			print("\nERROR: Key contains non hexadecimal digits, self.cur_appendage_value = "+str(self.cur_appendage_value))
			return -1, -1

		appendage 	= zero_pad(base, self.appendage_length)
		new_key 	= self.text+appendage
		
		self.cur_appendage_value += 1

		try:
			new_key_hex = new_key.decode("hex")
		except:
			print("\nERROR: Key contains non hexadecimal digits, new_key = "+str(new_key)+", appendage = "+str(appendage))
			return -1, -1

		return [new_key.decode("hex"), new_key]

	# Returns the same thing as get_key but encoded into letters/numbers
	def view_key(self, increment=False):

		base 		= hex(self.cur_appendage_value)[2:]
		appendage 	= zero_pad(base, self.appendage_length)
		new_key 	= self.text+appendage

		if increment: self.cur_appendage_value += 1
		return new_key

# Class to manage loading of current ciphertext file.
class ciphertext_t:

	def __init__(self, filename):

		self.src_filename 	= filename
		f 					= open(filename, 'rb')
		self.text 			= f.readline()
		self.prepared_text 	= self.text.decode("hex")


	def data(self):
		return self.prepared_text


# Pads the input_str with 0 (left) until its targ_length long. If the hex number
# is over a certain length Python will append a an "L" character to designate that
# its of type "long" so we need to check and remove that.
def zero_pad(input_str, targ_length):

	input_str = input_str.replace("L","")

	if len(input_str) > targ_length:

		input_str = input_str.replace("L","")

		if len(input_str) == targ_length:
			return input_str

		print ("\nERROR: targ_length input ("+str(targ_length)+") greater than length of input_str ("+str(input_str)+") --> [zero_pad()].\n")
		return ""

	while len(input_str)!=targ_length:
		input_str = "0"+input_str

	return input_str

# Encrypts a single block of ciphertext using key provided
def encrypt(plaintext, key_128):

	encryptor 	= AES.new(key_128, AES.MODE_ECB)
	ciphertext 	= encryptor.encrypt(plaintext)
	return ciphertext

# Decrypts a single block of ciphertext using key provided
def decrypt(ciphertext, key_128):

	decryptor = AES.new(key_128, AES.MODE_ECB)
	plaintext = decryptor.decrypt(ciphertext)
	return plaintext


lowercase = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z']
puncuation= [',','.','?','!',' ','\x00']
uppercase = ['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z']
numbers = ['0','1','2','3','4','5','6','7','8','9']
all_allowed_chars = lowercase+uppercase+puncuation+numbers

# Checks that every character in input_str is contained in one
# of the character sets above. If not, it returns false. If true
# this signifies that input_str is the plaintext because it only
# contains english words and numbers and puncuation.
def check_plaintext(input_str):

	for character in input_str:
		if character not in all_allowed_chars:
			return False

	return True

# Same as the check_plaintext function but takes in a list of possible
# plaintexts and checks them all, if none are the plaintext then it returns
# False and -1 and if one of them is okay it returns True and the index of the
# one that is the plaintext.
def check_plaintext_buffer(input_list):

	index = 0
	for input_str in input_list:

		if check_plaintext(input_str):
			return True, index

		index += 1

	return False,-1


