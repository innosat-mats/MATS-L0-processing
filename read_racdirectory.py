##########################################
#Loops through all .rac files for a given day and extracts payload data and stores it 
#as Python dicts. (Later store in SQL database) 
##########################################

#Created 17.03.09 Ole Martin Christensen

#This lists all .rac files and extracts them. Result in one large python dict containing all files from that
#day and one dict with all images
#
#Currently the code saves data multiple times, in particular the images are save as both hex, 
#binary (to be written out to .jpeg) and .png files, as well as in the original packets. 
#
#remove import of print function after upgrade to python 3
from __future__ import print_function

from os import listdir
from os import remove
import numpy as np
from read_racfile import read_racfile
from read12bit import read12bit_jpeg
import json
from JSON_Encoder import JSON_Encoder
import binascii
import matplotlib.pyplot as plt
from libtiff import TIFF
import cv2
import os

#import json

AllDataSorted = [] #List of dicts. Each entry is a packet
CCD_image_data = {} #List of dicts. Each entry is a CCD image
CCD_meta_data = {}


def read_racdirectory(in_directory,out_directory):
    dirName = out_directory + str('/JSON/')
    if not os.path.exists(dirName):
        os.makedirs(dirName)
        print("Directory " , dirName ,  " Created ")
    else:    
        print("Directory " , dirName ,  " already exists")

    dirName = out_directory + str('/IMAGES/')
    if not os.path.exists(dirName):
        os.makedirs(dirName)
        print("Directory " , dirName ,  " Created ")
    else:    
        print("Directory " , dirName ,  " already exists")



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
    CCD_image_data['data channel 4'] = []
    CCD_image_data['data channel 5'] = []
    CCD_image_data['data channel 6'] = []
    CCD_image_data['data channel 7'] = []
    
    #data needed for saving actual image to either jpg or pnm-file
    CCD_meta_data['data channel 1'] = []
    CCD_meta_data['data channel 2'] = []
    CCD_meta_data['data channel 3'] = []
    CCD_meta_data['data channel 4'] = []
    CCD_meta_data['data channel 5'] = []
    CCD_meta_data['data channel 6'] = []
    CCD_meta_data['data channel 7'] = []

    
    
    for j in range(0,7):
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
                    
                    CCD_meta_data['data channel '+str(j+1)][n]['SID_mnemonic']=AllDataSorted[x]['Source_data']['SID_mnemonic']
                    CCD_meta_data['data channel '+str(j+1)][n]['CCDSEL']=AllDataSorted[x]['Source_data']['CCDSEL']
                    CCD_meta_data['data channel '+str(j+1)][n]['EXPTS']=AllDataSorted[x]['Source_data']['EXPTS']
                    CCD_meta_data['data channel '+str(j+1)][n]['EXPTSS']=AllDataSorted[x]['Source_data']['EXPTSS']
                    CCD_meta_data['data channel '+str(j+1)][n]['WDW']=AllDataSorted[x]['Source_data']['WDW']
                    CCD_meta_data['data channel '+str(j+1)][n]['WDWOV']=AllDataSorted[x]['Source_data']['WDWOV']
                    CCD_meta_data['data channel '+str(j+1)][n]['JPEGQ']=AllDataSorted[x]['Source_data']['JPEGQ']
                    #CCD_meta_data['data channel '+str(j+1)][n]['FRAME']=AllDataSorted[x]['Source_data']['FRAME']
                    CCD_meta_data['data channel '+str(j+1)][n]['NROW']=AllDataSorted[x]['Source_data']['NROW']
                    CCD_meta_data['data channel '+str(j+1)][n]['NRBIN']=AllDataSorted[x]['Source_data']['NRBIN']
                    CCD_meta_data['data channel '+str(j+1)][n]['NRSKIP']=AllDataSorted[x]['Source_data']['NRSKIP']
                    CCD_meta_data['data channel '+str(j+1)][n]['NCOL']=AllDataSorted[x]['Source_data']['NCOL']
                    CCD_meta_data['data channel '+str(j+1)][n]['NCBIN']=AllDataSorted[x]['Source_data']['NCBIN']
                    CCD_meta_data['data channel '+str(j+1)][n]['NROW']=AllDataSorted[x]['Source_data']['NROW']
                    CCD_meta_data['data channel '+str(j+1)][n]['NCOL']=AllDataSorted[x]['Source_data']['NCOL']
                    CCD_meta_data['data channel '+str(j+1)][n]['NCBIN']=AllDataSorted[x]['Source_data']['NCBIN']
                    CCD_meta_data['data channel '+str(j+1)][n]['NCSKIP']=AllDataSorted[x]['Source_data']['NCSKIP']
                    CCD_meta_data['data channel '+str(j+1)][n]['NFLUSH']=AllDataSorted[x]['Source_data']['NFLUSH']
                    CCD_meta_data['data channel '+str(j+1)][n]['TEXPMS']=AllDataSorted[x]['Source_data']['TEXPMS']
                    CCD_meta_data['data channel '+str(j+1)][n]['GAIN']=AllDataSorted[x]['Source_data']['GAIN']
                    #CCD_meta_data['data channel '+str(j+1)][n]['TEMP']=AllDataSorted[x]['Source_data']['TEMP']
                    #CCD_meta_data['data channel '+str(j+1)][n]['FBINOV']=AllDataSorted[x]['Source_data']['FBINOV']
                    #CCD_meta_data['data channel '+str(j+1)][n]['LBLNK']=AllDataSorted[x]['Source_data']['LBLNK']
                    #CCD_meta_data['data channel '+str(j+1)][n]['TBLNK']=AllDataSorted[x]['Source_data']['TBLNK']
                    #CCD_meta_data['data channel '+str(j+1)][n]['ZERO']=AllDataSorted[x]['Source_data']['ZERO']
                    #CCD_meta_data['data channel '+str(j+1)][n]['TIMING1']=AllDataSorted[x]['Source_data']['TIMING1']
                    #CCD_meta_data['data channel '+str(j+1)][n]['TIMING2']=AllDataSorted[x]['Source_data']['TIMING2']
                    #CCD_meta_data['data channel '+str(j+1)][n]['VERSION']=AllDataSorted[x]['Source_data']['VERSION']
                    #CCD_meta_data['data channel '+str(j+1)][n]['TIMING3']=AllDataSorted[x]['Source_data']['TIMING3']
                    CCD_meta_data['data channel '+str(j+1)][n]['NBC']=AllDataSorted[x]['Source_data']['NBC']
                    CCD_meta_data['data channel '+str(j+1)][n]['BC']=AllDataSorted[x]['Source_data']['BC']

                    
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

    for j in range(0,7):#loop over channels again
        for i in range(len(CCD_image_data['data channel '+str(j+1)])):
    #    #Write images out as jpeg images
            CCD_image_data['data channel '+str(j+1)][i]['filename'] = ''
            if (CCD_image_data['data channel '+str(j+1)][i].get('error') == 0):
    #check JPEGQ to determine type of image (jpg or uncompressed)           
                if (CCD_meta_data['data channel '+str(j+1)][i].get('JPEGQ')<=100):
    #compressed image data is save to 12bit jpeg file, which is converted into a pnm file and the re-read into python as usigned 16 bit integer
    #the 16 bit data is plotted and save into a png file
                    filename = out_directory + '/IMAGES/' + str(CCD_meta_data['data channel '+str(j+1)][i]['EXPTS'][0]) +'_'+ str(CCD_meta_data['data channel '+str(j+1)][i]['EXPTSS'][0]) + '.jpg'
                    print(str('Writing file ' + filename[:-4] + '.png'))
                    CCD_image_data['data channel '+str(j+1)][i]['filename'] = filename

                    with open(filename,'w') as f:
                        f.write(CCD_image_data['data channel '+str(j+1)][i]['image'])
                    
                    im_data=read12bit_jpeg(filename)

                    remove(filename)
                    remove(filename[:-4]+'.pnm')
                    
                else:
    #uncompressed data is plotted and save to png file for visual (!) inspection
    #pnm files introduced apparent pixeloverflows
    #uncompressed image data itself can be retrieved from corresponding json files
                    filename = out_directory + '/IMAGES/' + str(CCD_meta_data['data channel '+str(j+1)][i]['EXPTS'][0]) +'_'+ str(CCD_meta_data['data channel '+str(j+1)][i]['EXPTSS'][0]) + '.png'
                    print(str('Writing file ' + filename))
                    CCD_image_data['data channel '+str(j+1)][i]['filename'] = filename
                    cols=int(CCD_meta_data['data channel '+str(j+1)][i]['NCOL'])+1
                    rows=int(CCD_meta_data['data channel '+str(j+1)][i]['NROW'])
                    image_data=CCD_image_data['data channel '+str(j+1)][i]['image']
                    im_data=np.frombuffer(image_data, dtype=np.uint16)
                    
                    im_data=np.reshape(im_data,(rows,cols))
                    
                    
            fig, ax = plt.subplots()
            im=ax.pcolor(im_data)
            ax.set_aspect('equal')
            ax.set_ylim(ax.get_ylim()[::-1])
            fig.colorbar(im,ax=ax,fraction=0.0305)
            plt.tight_layout()
            plt.savefig(filename[:-4] + ".png")
            cv2.imwrite(filename[:-4] + "_data.png",im_data.astype(np.uint16))
            np.save(filename[:-4] + "_data.npy",im_data)
            plt.close(fig)

                    
#end loop over channels
        
    filename = out_directory + '/JSON/images.json'
    with open(filename, 'w') as outfile:
        print(str('Writing file ' + filename))
        json.dump(CCD_meta_data, outfile, sort_keys = True, indent = 4,
               ensure_ascii = False,cls=JSON_Encoder)
    
    return AllDataSorted, CCD_image_data
