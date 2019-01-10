#remove import of print function after upgrade to python 3
from __future__ import print_function

import numpy
from read_packet import read_packet
#import binascii

##########################################
#This function takes in MATS payload data and reads one .rac file and extracts it. 
##########################################
#Created 17.03.09 Ole Martin Christensen



def read_racfile(filename):

    data = numpy.fromfile(filename,'uint8') #read in binary data
    pointer = 0; #start reading at start of file
    AllData = []
    while pointer < data.size: #loop over entire file
        [p,pointer] = read_packet(data,pointer) #read package starting at file pointer p
        if bool(p) == True: 
            AllData.append(p) #append data from package
    
    #AllDataSorted is a list with one entry for each package
    AllDataSorted = sorted(AllData, key = lambda user: user['SPH_source_sequence_count']) #Sort based on sequence counts
                             
    return AllDataSorted#, CCD_image_data
    

