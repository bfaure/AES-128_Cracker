from __future__ import print_function
import time
import threading

from utils import key_t,validate,ciphertext_t,decrypt,check_plaintext,check_plaintext_buffer,test_result,file_stats

src_dir 		= "Computer Project 1/" 
key_length 		= 32 # Number of characters in key
found 			= False # Set to true by consumer thread that finds the plaintext
searched 		= 0 # Number of total keys tested by (incremented by all threads)
buffer_size 	= 1024 # NOT USED
check_buffer 	= True # If true, consumer threads will check for things to consumer from output_buffer
output_buffer 	= [] # Holds the elements (key - plaintext pairs held in test_result structs) produced by producer threads
extra_consumers = 1 # Number of extra consumer threads to start when decrypting

from utils import max_keys_in_list as MAX_BUFFER_LENGTH

EXEC_THREAD_SLEEP_TIME 		= 0.01 # Amt of time for producer threads to sleep if there are too many elements on output_buffer
OUTPUT_SPY_SLEEP_TIME 		= 0.05 # Amt of time for consumer threads to sleep if there are no elements on output_buffer
BUFFER_MEMORY_MULTIPLIER 	= 25 # Allowed list length (multiplier) over the total length each thread deals with (for output_buffer)

# CONSUMER PROCEDURE
# Constantly checks the output_buffer and pulls the first one
# off the top to check if its the correct plaintext.
def output_spy(file_set="0"):
	global found
	global check_buffer

	while check_buffer:

		if len(output_buffer)>0:
			
			try:
				result = output_buffer.pop()
			except:
				continue

			is_english = check_plaintext(result.found_plaintext)

			if is_english:
				found = True
				check_buffer = False
				filename = "results-[Cipherfile"+file_set+"]-[Version "+str(time.time())+"].txt"
				f = open(filename, 'w')
				print("\nOutput spy found plaintext: "+str(result.found_plaintext))
				print ("Writing results to "+filename)
				result.write_to_file(f)
				return
		else:
			time.sleep(OUTPUT_SPY_SLEEP_TIME)

# PRODUCER PROCEDURE
# Performs a sequential search of the entire keyspace (unless threading 
# is being used, see next comment section if so) and stops execution when
# it finds a plaintext that satisfies the check_plaintext function.

# If multithreading is being used, each instance of this function will
# have its own thread number as well as a search range to search over such
# that the keyspace is split evenly over all threads. If one of the threads
# suceeds to find the value this thread will finish execution.

# Working as a producer, each thread of this function will push the calculated
# plaintext strings onto the output_buffer list to be checked by the consumer
# threads when they pop the values off. (i.e. this function does not perform
# any of the plaintext checking)
def brute_force_crack(file_set="0",thread_num=0,start_search=0,end_search=0):
	global found
	global searched

	ciphertext_filename = src_dir+"Cipherfile"+file_set+".txt"
	iv_filename 		= src_dir+"IVfile"+file_set+".txt"
	key_manager 		= key_t(iv_filename,thread_num,start_search,end_search)
	ciphertext_manager 	= ciphertext_t(ciphertext_filename)
	ciphertext 			= ciphertext_manager.data()
	keys 				= []

	keys = key_manager.get_keys()

	while(True):

		for elem in keys:

			# The key_manager creates an arbitrary -2 value to signify that
			# we need to call it again to get the next portion of keys because
			# the initial amount was too large to fit in a single transfer.
			if elem[0] == -2:
				keys = key_manager.get_keys()
				break

			if len(output_buffer) > (MAX_BUFFER_LENGTH*BUFFER_MEMORY_MULTIPLIER):
				time.sleep(EXEC_THREAD_SLEEP_TIME)

			cur_key = elem[0]
			clean 	= elem[1]

			if found:
				return

			# If the key_manager function returns -1 it means this thread has reached the end of
			# the keyspace it was designated to search through so we break.
			if cur_key == -1:
				return

			cur_plaintext 	= decrypt(ciphertext,cur_key)
			cur_result 		= test_result(cur_plaintext,cur_key,clean)
			output_buffer.append(cur_result)

			searched 		+=1

	return

# Wraps the brute_force_crack function to allow for multithreading. Each instance of
# the brute_force_crack function is provided a subset of the overall keyspace to search.
# The size of the effective keyspace equals the keyspace divided by the number of threads
# being used to crack.
def crack_threaded(file_set="1",num_threads=4):
	global found
	global searched
	global check_buffer

	iv_filename 		= src_dir+"IVfile"+file_set+".txt"
	key_manager 		= key_t(iv_filename)

	keyspace 			= key_manager.get_keyspace()
	search_per_thread 	= keyspace/num_threads
	
	cur_start 			= 0
	cur_end 			= cur_start+search_per_thread

	producer_pool 		= []
	consumer_pool		= []

	print ("--> Initializing ["+str(num_threads)+"] producer/consumer thread pool[s]...")

	found 		= False
	searched 	= 0
	check_buffer= True

	start_time 	= time.time()

	for i in range(num_threads):

		producer = threading.Thread(target=brute_force_crack, args=(file_set,i,cur_start,cur_end))
		producer_pool.append(producer)

		consumer = threading.Thread(target=output_spy, args=(file_set))
		consumer_pool.append(consumer)

		cur_start 	+= search_per_thread
		cur_end 	+= search_per_thread

	extra_consumer_pool = []
	
	for _ in range(extra_consumers):
		consumer = threading.Thread(target=output_spy,args=(file_set))
		extra_consumer_pool.append(consumer)

	for producer,consumer in list(zip(producer_pool,consumer_pool)):
		consumer.start()
		producer.start()

	for extra_consumer in extra_consumer_pool:
		extra_consumer.start()

	print ("--> "+str(num_threads)+" thread pool[s] online...")

	# Busy wait until one of the consumer threads has found the plaintext
	ctr = 0
	while(found==False):
		ctr+=1
		if ctr == 100:
			print ("                                                                                                                                ",end="\r")
			ctr=0

		time.sleep(0.2)
		if found==False:
			print ("Keys Tested: "+str(searched)+", \tKeyspace Searched: "+str(float(float(searched)/float(keyspace))*100.0)+" %, \tKeys/Second: "+str((searched/(time.time()-start_time)))+", \tBuffer Size: "+str(len(output_buffer)),end="\r")

	full_time = time.time()-start_time

	time.sleep(0.1)

	print ("\nTotal execution time: "+str(full_time)+" seconds.")
	print ("Total number of keys tested: "+str(searched))
	print ("Total searchable keyspace: "+str(keyspace))

	print ("All threads offline.")
	return str(full_time),searched


# Decrypts each set of files (starting with Cipherfile1). For each it will
# perform the same and log results to separate text files.
def testing_suite(file_set="1",thread_sets=[1,2,4,8,10,12,15,20,30,40,50,60,75,100,200]):

	test_data_filename 	= "testing_data-[Cipherfile"+file_set+"]-[Version "+str(time.time())+"].txt"
	test_data 			= open(test_data_filename, 'w')
	header 				= str("[----------Decrypting Cipherfile"+file_set+".txt----------]")
	
	print(header)

	test_data.write("Number of Threads: \n")

	for num in thread_sets:
		test_data.write(str(num)+"\n")

	test_data.write("\n\nExecution Time: \n")

	exec_times = []
	comparison_cts = []

	for num_threads in thread_sets:

		text = "\n[---------------With "+str(num_threads)+" thread[s]--------------]"
		
		print(text)

		exec_time,num_comparisons = crack_threaded(file_set,num_threads)

		exec_times.append(exec_time)
		comparison_cts.append(num_comparisons)
	
	for cur_exec_time in exec_times:
		test_data.write(str(cur_exec_time)+"\n")

	test_data.write("\n\nKeys Checked: \n")

	for cur_comparison_ct in comparison_cts:
		test_data.write(str(cur_comparison_ct)+"\n")

	test_data.close()

testing_thread_set 		= [1,2,4,8,10,12,15,20,30,40,50,60,75,100,200]
performance_thread_set	= [3,10,50,150]
singular_thread_set		= [1]

def main():

	validate()
	#file_stats()
	testing_suite(file_set="4",thread_sets=[4])


if __name__ == '__main__':
	main()