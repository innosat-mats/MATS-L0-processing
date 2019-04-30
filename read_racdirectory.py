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
import numpy as np
from read_racfile import read_racfile
import json
from JSON_Encoder import JSON_Encoder
import binascii
from PIL import Image
import matplotlib.pyplot as plt
#import cv

#import json

AllDataSorted = [] #List of dicts. Each entry is a packet
CCD_image_data = {} #List of dicts. Each entry is a CCD image
CCD_meta_data = {}

def read_racdirectory(in_directory,out_directory):
    allFiles = listdir(in_directory)
    for i in range(len(allFiles)):
       print(str('Reading file ' + in_directory + '/' + allFiles[i]))
       #tmp1,tmp2 = read_racfile(in_directory + '/' + allFiles[i])
       tmp1 = read_racfile(in_directory + '/' + allFiles[i])
       AllDataSorted.extend(tmp1)
       
    #Merge CCD data from several files
    print(str('Joining images'))
    CCD_image_data['data channel 1'] = []
    CCD_image_data['data channel 2'] = []
    CCD_image_data['data channel 3'] = []
    
    #data needed for saving actual image to either jpg or pnm-file
    CCD_meta_data['data channel 1'] = []
    CCD_meta_data['data channel 2'] = []
    CCD_meta_data['data channel 3'] = []
    
    
    for j in range(0,3):
        print('CCD data channel '+str(j+1))
        #loop over channels
    
        n = -1
        for x in range(0,len(AllDataSorted)):
            if AllDataSorted[x]['Source_data']['SID_mnemonic'] == ['CCD data channel '+str(j+1)]:
                if AllDataSorted[x]['SPH_grouping_flags'] == '01' or AllDataSorted[x]['SPH_grouping_flags'] == '11':
                    n = n+1 #start new image
                    #print 'CCD data start'
                    CCD_image_data['data channel '+str(j+1)].append({}) #start new image
                    CCD_image_data['data channel '+str(j+1)][n]['data'] = [] 
                    CCD_image_data['data channel '+str(j+1)][n]['start'] = x 
                    CCD_image_data['data channel '+str(j+1)][n]['cont'] = [] 
                    CCD_image_data['data channel '+str(j+1)][n]['stop'] = []
                    #Add data to image
                    CCD_image_data['data channel '+str(j+1)][n]['data'].append(AllDataSorted[x]['Source_data']['IMG'])
                    
                    CCD_meta_data['data channel '+str(j+1)].append({})
                    CCD_meta_data['data channel '+str(j+1)][n]['JPEGQ']=AllDataSorted[x]['Source_data']['JPEGQ']
                    CCD_meta_data['data channel '+str(j+1)][n]['NROW']=AllDataSorted[x]['Source_data']['NROW']
                    CCD_meta_data['data channel '+str(j+1)][n]['NCOL']=AllDataSorted[x]['Source_data']['NCOL']
                    
                elif AllDataSorted[x]['SPH_grouping_flags'] == '10':
                    #print 'CCD data stop'
                    CCD_image_data['data channel '+str(j+1)][n]['stop'] = x 
                    CCD_image_data['data channel '+str(j+1)][n]['data'].append(AllDataSorted[x]['Source_data']['IMG'])
                elif AllDataSorted[x]['SPH_grouping_flags'] == '00':
                    if not CCD_image_data['data channel '+str(j+1)]:
                        print('Warning: current .rac file started with continued CCD data for this channel')
                        if n==-1:#currently a work-around
                            CCD_image_data['data channel '+str(j+1)].append({})
                            CCD_image_data['data channel '+str(j+1)][n+1]['cont'] = []
                            CCD_image_data['data channel '+str(j+1)][n+1]['data'] = []
                    CCD_image_data['data channel '+str(j+1)][n]['cont'].append(x) 
                    CCD_image_data['data channel '+str(j+1)][n]['data'].append(AllDataSorted[x]['Source_data']['IMG'])
            
        for x in range(0,len(CCD_image_data['data channel '+str(j+1)])):
            #get-function allows to check if keywords are existing or not
            if CCD_image_data['data channel '+str(j+1)][x].get('start')!=None and CCD_image_data['data channel '+str(j+1)][x].get('stop')!=None:
                if CCD_image_data['data channel '+str(j+1)][x]['start'] and CCD_image_data['data channel '+str(j+1)][x]['stop']:
                    a = "".join(CCD_image_data['data channel '+str(j+1)][x]['data'])
                    CCD_image_data['data channel '+str(j+1)][x]['image'] = binascii.unhexlify(a)
                    CCD_image_data['data channel '+str(j+1)][x]['error'] = 0
                else:
                    print('Warning: start or stop does not exist for image: ' + str(x)+', channel '+str(j+1))
                    CCD_image_data['data channel '+str(j+1)][x]['error'] = 1
            else:
                print('Warning: start or stop key does not exist for image: ' + str(x)+', channel '+str(j+1))
                CCD_image_data['data channel '+str(j+1)][x]['error'] = 1
       
     #end channel loop  
    
    filename = out_directory + '/JSON/packets.json'
    with open(filename, 'w') as outfile:
        print(str('Writing file ' + filename))
        json.dump(AllDataSorted, outfile, sort_keys = True, indent = 4,
               ensure_ascii = False,cls=JSON_Encoder)

    for j in range(0,3):#loop over channels again
        for i in range(len(CCD_image_data['data channel '+str(j+1)])):
    #    #Write images out as jpeg images (for conversion in matlab)
            CCD_image_data['data channel '+str(j+1)][i]['filename'] = ''
            if (CCD_image_data['data channel '+str(j+1)][i].get('error') == 0):
    #check JPEGQ to determine type of image (jpg or uncompressed)           
                if (CCD_meta_data['data channel '+str(j+1)][i].get('JPEGQ')<=100):
                    filename = out_directory + '/IMAGES/test_channel'+str(j+1)+'_'+ str(i) + '.jpg'
                    print(str('Writing file ' + filename))
                    CCD_image_data['data channel '+str(j+1)][i]['filename'] = filename
                    with open(filename,'w') as f:
                        f.write(CCD_image_data['data channel '+str(j+1)][i]['image'])
                else:
    #uncompressed data is plotted and save to png file for visual (!) inspection
    #pnm files introduced apparent pixeloverflows
    #uncompressed image data itself can be retrieved from corresponding json files
                    filename = out_directory + '/IMAGES/test_channel'+str(j+1)+'_'+ str(i) + '.png'
                    print(str('Writing file ' + filename))
                    CCD_image_data['data channel '+str(j+1)][i]['filename'] = filename
                    cols=int(CCD_meta_data['data channel '+str(j+1)][i]['NCOL'])+1
                    rows=int(CCD_meta_data['data channel '+str(j+1)][i]['NROW'])
                    #pnm_header="P5\n"+str(cols)+" "+str(rows)+"\n65535\n"
                    image_data=CCD_image_data['data channel '+str(j+1)][i]['image']
                    im_data=np.frombuffer(image_data, dtype=np.uint16)
                    
                    #with open(filename,'w') as f:
                        #f.write(pnm_header)
                        #f.write(image_data.byteswap().tobytes())
                        #f.write(image_data)
                    
                    im_data=np.reshape(im_data,(rows,cols))
                    fig, ax = plt.subplots()
                    im=ax.pcolor(im_data)
                    ax.set_aspect('equal')
                    ax.set_ylim(ax.get_ylim()[::-1])
                    fig.colorbar(im,ax=ax,fraction=0.0305)
                    plt.tight_layout()
                    plt.savefig(filename)


                    
#end loop over channels
        
    filename = out_directory + '/JSON/images.json'
    with open(filename, 'w') as outfile:
        print(str('Writing file ' + filename))
        json.dump(CCD_image_data, outfile, sort_keys = True, indent = 4,
               ensure_ascii = False,cls=JSON_Encoder)
    
    return AllDataSorted, CCD_image_data
