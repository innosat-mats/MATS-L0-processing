#remove import of print function after upgrade to python 3
from __future__ import print_function

import numpy
from read_packet_ICD_Issue_H import read_packet
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
    count=numpy.zeros(len(AllData))
    num_resetted_counter=[]
    SPH_count_pre_reset=[]
    for i in range(len(AllData)):
        count[i] = AllData[i].get('SPH_source_sequence_count')  
        if count[i]<count[i-1]:
            print('WARNING: SPH cource sequence count was reset at paket: '+str(i))
            num_resetted_counter.append(i)
            SPH_count_pre_reset.append(count[i-1])
    
    counter_reset_diagnostic=[num_resetted_counter, SPH_count_pre_reset]
    
    #AllDataSorted = sorted(AllData, key = lambda user: (user['DFH_CUC_time_seconds'], user['DFH_CUC_time_fraction']))
                             
    return AllData#, CCD_image_data
    

