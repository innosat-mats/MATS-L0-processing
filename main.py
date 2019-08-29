#main file to test MATS processing

from read_racdirectory import read_racdirectory

#filename = "../Payload_20161116-132455_20161116-134915.rac"
date = "2017-01-01"
#in_directory = "./FTP/TM/1/100/" + date
#out_directory = "./L0_data/" + date
in_directory = "rac-files"
out_directory = "rac-out"
a, b = read_racdirectory(in_directory,out_directory)
