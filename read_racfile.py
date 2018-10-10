#remove import of print function after upgrade to python 3
from __future__ import print_function

import numpy
from read_packet import read_packet
import binascii

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
        AllData.append(p) #append data from package
    
    #AllDataSorted is a list with one entry for each package
    AllDataSorted = sorted(AllData, key = lambda user: user['SPH_source_sequence_count']) #Sort based on sequence counts
    
    
    
    #Merge CCD data from several packets
    print(str('Joining images'))
    CCD_image_data = []
    n = -1
    for x in range(0,len(AllDataSorted)):
        if AllDataSorted[x]['Source_data']['SID_mnemonic'] == ['CCD data channel 1']:
            if AllDataSorted[x]['SPH_grouping_flags'] == '01':
                n = n+1 #start new image
                #print 'CCD data start'
                CCD_image_data.append({}) #start new image
                CCD_image_data[n]['data'] = [] 
                CCD_image_data[n]['start'] = x 
                CCD_image_data[n]['cont'] = [] 
                CCD_image_data[n]['stop'] = []
                #Add data to image
                CCD_image_data[n]['data'].append(AllDataSorted[x]['Source_data']['CCD_image_data'])
            elif AllDataSorted[x]['SPH_grouping_flags'] == '10':
                #print 'CCD data stop'
                CCD_image_data[n]['stop'] = x 
                CCD_image_data[n]['data'].append(AllDataSorted[x]['Source_data']['CCD_image_data'])
            elif AllDataSorted[x]['SPH_grouping_flags'] == '00':
                CCD_image_data[n]['cont'].append(x) 
                CCD_image_data[n]['data'].append(AllDataSorted[x]['Source_data']['CCD_image_data'])
                
    for x in range(0,len(CCD_image_data)):
        if CCD_image_data[x]['start'] and CCD_image_data[x]['stop']:
            a = "".join(CCD_image_data[x]['data'])
            CCD_image_data[x]['image'] = binascii.unhexlify(a)
            CCD_image_data[x]['error'] = 0
        else:
            print('Warning: start or stop does not exist for image: ' + str(x))
            CCD_image_data[x]['error'] = 1
                          
    return AllDataSorted, CCD_image_data
    

