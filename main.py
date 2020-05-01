#main file to test MATS processing

from read_racdirectory import read_racdirectory

#filename = "../Payload_20161116-132455_20161116-134915.rac"
#date = "2017-01-01"
in_directory = "./test/"
#out_directory = "./L0_data/" + date
out_directory = "out"
a, b = read_racdirectory(in_directory,out_directory)
