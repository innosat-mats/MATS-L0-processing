##########################################
#Loops through all .rac files for a given day and extracts payload data and stores it 
#as Python dicts. (Later store in SQL database) 
##########################################

#Created 17.03.09 Ole Martin Christensen

#This lists all .rac files and extracts them. Result in one large python dict containing all files from that
#day and one dict with all images
#
#Currently the code saves data multiple times, in particular the images are save as both hex, 
#binary (to be written out to .jpeg) and .jpeg files, as well as in the original packets. 
#
#remove import of print function after upgrade to python 3
from __future__ import print_function

from os import listdir
from read_racfile import read_racfile
import json
from JSON_Encoder import JSON_Encoder

#import json

AllDataSorted = [] #List of dicts. Each entry is a packet
CCD_image_data = [] #List of dicts. Each entry is a CCD image

def read_racdirectory(in_directory,out_directory):
    allFiles = listdir(in_directory)
    for i in range(len(allFiles)):
       print(str('Reading file ' + in_directory + '/' + allFiles[i]))
       tmp1,tmp2 = read_racfile(in_directory + '/' + allFiles[i])
       AllDataSorted.extend(tmp1)
       CCD_image_data.extend(tmp2)

    filename = out_directory + '/JSON/packets.json'
    with open(filename, 'w') as outfile:
        print(str('Writing file ' + filename))
        json.dump(AllDataSorted, outfile, sort_keys = True, indent = 4,
               ensure_ascii = False,cls=JSON_Encoder)

    for i in range(len(CCD_image_data)):
    #    #Write images out as jpeg images (for conversion in matlab)
        CCD_image_data[i]['filename'] = ''
        if (CCD_image_data[i]['error'] == 0):
            filename = out_directory + '/IMAGES/test' + str(i) + '.jpg'
            print(str('Writing file ' + filename))
            CCD_image_data[i]['filename'] = filename
            with open(filename,'w') as f:
                f.write(CCD_image_data[i]['image'])
                

        
    filename = out_directory + '/JSON/images.json'
    with open(filename, 'w') as outfile:
        print(str('Writing file ' + filename))
        json.dump(CCD_image_data, outfile, sort_keys = True, indent = 4,
               ensure_ascii = False,cls=JSON_Encoder)
    
    return AllDataSorted, CCD_image_data