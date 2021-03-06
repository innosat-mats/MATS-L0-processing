##########################################
#Loops through all .rac files for a given day and extracts payload data and stores it 
#as Python dicts. (Later store in SQL database) 
##########################################

#Created 17.03.09 Ole Martin Christensen

#This lists all .rac files and extracts them. Alternativly reads a single rac file. Result in one large python dict containing all files from that
#day and one dict with all images
#
#Currently the code saves data multiple times, in particular the images are save as both hex, 
#binary (to be written out to .jpeg) and .png files, as well as in the original packets. 
#
#remove import of print function after upgrade to python 3
from __future__ import print_function

from os import listdir
from os import remove
import sys
import numpy as np
from read_racfile import read_racfile
from read12bit import read12bit_jpeg
import json
from JSON_Encoder import JSON_Encoder
import binascii
import matplotlib.pyplot as plt
import cv2
import os
import math


NANOS_PER_SECOND = 1e9

#import json

AllDataSorted = [] #List of dicts. Each entry is a packet
CCD_image_data = {} #List of dicts. Each entry is a CCD image
#CCD_meta_data = {}


def read_racdirectory(in_directory,out_directory=''):
    if out_directory == '':
      if os.path.isfile(in_directory):
        out_directory = in_directory[:-4]
      else:
        out_directory = os.path.normpath(in_directory) + '_out'
      
    dirName = out_directory
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


    if os.path.isdir(in_directory):
        print("Reading from directory ", in_directory)
        allFiles = sorted(listdir(in_directory), key=str.lower)
        print("All files are: " , allFiles)
        for i in range(len(allFiles)):
            print(str('Reading file ' + in_directory + '/' + allFiles[i]))
            #tmp1,tmp2 = read_racfile(in_directory + '/' + allFiles[i])
            tmp1 = read_racfile(in_directory + '/' + allFiles[i])
            AllDataSorted.extend(tmp1)
    else:
        tmp1 = read_racfile(in_directory)
        AllDataSorted.extend(tmp1)
            
       
    #Merge CCD data from several files
    print(str('Joining images'))
    CCD_image = []
#    CCD_image_data['data channel 1'] = []
#    CCD_image_data['data channel 2'] = []
#    CCD_image_data['data channel 3'] = []
#    CCD_image_data['data channel 4'] = []
#    CCD_image_data['data channel 5'] = []
#    CCD_image_data['data channel 6'] = []
#    CCD_image_data['data channel 7'] = []
    
#    #data needed for saving actual image to either jpg or pnm-file
#    CCD_meta_data['data channel 1'] = []
#    CCD_meta_data['data channel 2'] = []
#    CCD_meta_data['data channel 3'] = []
#    CCD_meta_data['data channel 4'] = []
#    CCD_meta_data['data channel 5'] = []
#    CCD_meta_data['data channel 6'] = []
#    CCD_meta_data['data channel 7'] = []

    
    
    
    n = -1
    for x in range(0,len(AllDataSorted)):
        if AllDataSorted[x]['Source_data']['SID'] in [21,22,23,24,25,26,27]:
            if AllDataSorted[x]['SPH_grouping_flags'] == '01' or AllDataSorted[x]['SPH_grouping_flags'] == '11':
                n = n+1 #start new image
                #print 'CCD data start'
                CCD_image.append({}) #start new image
                CCD_image[n]['data'] = [] 
                CCD_image[n]['start'] = x 
                CCD_image[n]['cont'] = [] 
                CCD_image[n]['stop'] = []
                #Add data to image
                CCD_image[n]['data'].append(AllDataSorted[x]['Source_data']['IMG'])
                
                CCD_image[n]['SID_mnemonic']=AllDataSorted[x]['Source_data']['SID_mnemonic']
                CCD_image[n]['CCDSEL']=AllDataSorted[x]['Source_data']['CCDSEL']
                CCD_image[n]['EXPTS']=AllDataSorted[x]['Source_data']['EXPTS']
                CCD_image[n]['EXPTSS']=AllDataSorted[x]['Source_data']['EXPTSS']
                CCD_image[n]['WDW']=AllDataSorted[x]['Source_data']['WDW']
                CCD_image[n]['WDWOV']=AllDataSorted[x]['Source_data']['WDWOV']
                CCD_image[n]['JPEGQ']=AllDataSorted[x]['Source_data']['JPEGQ']
                CCD_image[n]['FRAME']=AllDataSorted[x]['Source_data']['FRAME']
                CCD_image[n]['NROW']=AllDataSorted[x]['Source_data']['NROW']
                CCD_image[n]['NRBIN']=AllDataSorted[x]['Source_data']['NRBIN']
                CCD_image[n]['NRSKIP']=AllDataSorted[x]['Source_data']['NRSKIP']
                CCD_image[n]['NCOL']=AllDataSorted[x]['Source_data']['NCOL']
                CCD_image[n]['NCBIN']=AllDataSorted[x]['Source_data']['NCBIN']
                CCD_image[n]['NROW']=AllDataSorted[x]['Source_data']['NROW']
                CCD_image[n]['NCOL']=AllDataSorted[x]['Source_data']['NCOL']
                CCD_image[n]['NCBIN']=AllDataSorted[x]['Source_data']['NCBIN']
                CCD_image[n]['NCSKIP']=AllDataSorted[x]['Source_data']['NCSKIP']
                CCD_image[n]['NFLUSH']=AllDataSorted[x]['Source_data']['NFLUSH']
                CCD_image[n]['TEXPMS']=AllDataSorted[x]['Source_data']['TEXPMS']
                CCD_image[n]['GAIN']=AllDataSorted[x]['Source_data']['GAIN']
                CCD_image[n]['TEMP']=AllDataSorted[x]['Source_data']['TEMP']
                CCD_image[n]['FBINOV']=AllDataSorted[x]['Source_data']['FBINOV']
                CCD_image[n]['LBLNK']=AllDataSorted[x]['Source_data']['LBLNK']
                CCD_image[n]['TBLNK']=AllDataSorted[x]['Source_data']['TBLNK']
                CCD_image[n]['ZERO']=AllDataSorted[x]['Source_data']['ZERO']
                CCD_image[n]['TIMING1']=AllDataSorted[x]['Source_data']['TIMING1']
                CCD_image[n]['TIMING2']=AllDataSorted[x]['Source_data']['TIMING2']
                CCD_image[n]['VERSION']=AllDataSorted[x]['Source_data']['VERSION']
                CCD_image[n]['TIMING3']=AllDataSorted[x]['Source_data']['TIMING3']
                CCD_image[n]['NBC']=AllDataSorted[x]['Source_data']['NBC']
                CCD_image[n]['BC']=AllDataSorted[x]['Source_data']['BC']

                CCD_image[n]['id']=str(UnsegmentedTimeNanoseconds(CCD_image[n]['EXPTS'][0],CCD_image[n]['EXPTSS'][0])) + '_' + str(CCD_image[n]['CCDSEL'][0])

                # Extract variables from certain bits within the same element, see 6.4.1 Software ICD /LM 20191115               
                CCD_image[n]['NColBinFPGA'] = CCD_image[n]['NCBIN'] & (4096-256)
                CCD_image[n]['NColBinCCD'] = CCD_image[n]['NCBIN'] & 255
                del CCD_image[n]['NCBIN']
                CCD_image[n]['DigGain'] = CCD_image[n]['GAIN'] & 15 
                CCD_image[n]['TimingFlag'] = CCD_image[n]['GAIN'] & 256
                CCD_image[n]['SigMode'] =  CCD_image[n]['GAIN'] & 4096            
                del CCD_image[n]['GAIN']
                CCD_image[n]['WinModeFlag']=CCD_image[n]['WDW']& 128
                CCD_image[n]['WinMode']=CCD_image[n]['WDW']& 7
                del CCD_image[n]['WDW']
                
                
            elif AllDataSorted[x]['SPH_grouping_flags'] == '10':
                #print 'CCD data stop'
                CCD_image[n]['stop'] = x 
                CCD_image[n]['data'].append(AllDataSorted[x]['Source_data']['IMG'])
            elif AllDataSorted[x]['SPH_grouping_flags'] == '00':
                if not CCD_image: #if this is the first CCD image (i.e. CCD_image is empty)
                    print('Warning: current .rac file started with continued CCD data for this channel')
                    if n==-1:#currently a work-around
                        n = n+1
                        CCD_image.append({}) #start new image
                        CCD_image[n]['start'] = -1 #-1 indicates started in previous rac file 
                        CCD_image[n]['cont'] = [] 
                        CCD_image[n]['stop'] = []
                        CCD_image[n]['data'] = []
                    else:
                        raise ValueError('No image data, yet n > 0') 
                        
                else:
                    CCD_image[n]['cont'].append(x) 
                    CCD_image[n]['data'].append(AllDataSorted[x]['Source_data']['IMG'])
    print('Total ' + str(len(CCD_image)) + ' images read')    
    
    for x in range(0,len(CCD_image)):
        #get-function allows to check if keywords are existing or not
        if CCD_image[x].get('start')!=None and CCD_image[x].get('stop')!=None:
            if CCD_image[x]['start'] == -1 and CCD_image[x]['stop']: #no start, but a stop (from previous rac file)
                CCD_image[x]['packet_error'] = -1
                print('no start, but stop image number: ' + str(x))
            elif CCD_image[x]['start'] and not CCD_image[x]['stop']: #start, but no stop (continious to next rac file)
		       print('start, but no stop - image number ' + str(x) + ' IMAGE ID: ' + str(CCD_image[x]['id']))                
		       CCD_image[x]['packet_error'] = 1   
            elif CCD_image[x]['start'] and CCD_image[x]['stop']:
                a = "".join(CCD_image[x]['data'])
                CCD_image[x]['image_data'] = binascii.unhexlify(a)
                CCD_image[x]['packet_error'] = 0
            else:
                print('Warning: start or stop does not exist - image number ' + str(x) + ' IMAGE ID: ' + str(CCD_image[x]['id']))
                CCD_image[x]['packet_error'] = 2 
        else:
            print('Warning: start or stop key does not exist - image number ' + str(x) + ' IMAGE ID: ' + str(CCD_image[x]['id']))
            CCD_image[x]['packet_error'] = 3
        del CCD_image[x]['data']
     #end channel loop  
    
    filename = out_directory + '/packets.json'
    with open(filename, 'w') as outfile:
        print(str('Writing file ' + filename))
        json.dump(AllDataSorted, outfile, sort_keys = True, indent = 4,
               ensure_ascii = False,cls=JSON_Encoder)

    for i in range(len(CCD_image)):
#    #Write images out as jpeg images
        CCD_image[i]['filename'] = ''
        if (CCD_image[i].get('packet_error') == 0):
#check JPEGQ to determine type of image (jpg or uncompressed)           
            if (CCD_image[i].get('JPEGQ')<=100):
#compressed image data is save to 12bit jpeg file, which is converted into a pnm file and the re-read into python as usigned 16 bit integer
#the 16 bit data is plotted and save into a png file
                filename = out_directory + '/IMAGES/' + str(CCD_image[i]['id'])
                print(str('Writing file ' + filename))
                CCD_image[i]['filename'] = filename

                with open(filename,'w') as f:
                    f.write(CCD_image[i]['image_data'])
                
                im_data=read12bit_jpeg(filename)
                
                #Delete temporary files generated by read12bitjpeg
                remove(filename)
                remove(filename +'.pnm')
                
            else:
                #uncompressed data is plotted and save to png file for visual (!) inspection                              
              
                filename = out_directory + '/IMAGES/' + str(CCD_image[i]['id'])
                print(str('Writing file ' + filename))
                CCD_image[i]['filename'] = filename
                image_data=CCD_image[i]['image_data']
                im_data=np.frombuffer(image_data, dtype=np.uint16)
            
            cols=int(CCD_image[i]['NCOL'])+1
            rows=int(CCD_image[i]['NROW'])
            try:
                im_data=np.reshape(im_data,(rows,cols))
            except ValueError:
                ValueError('Shape of image wrong, missing data, files or wrong filenames (are all rac files in chronological order?)')

            CCD_image[i]['imagefile'] = filename
            #Can be used to store the image data directly
            #CCD_image[i]['IMAGE16bit'] = im_data.astype(np.uint16) 
            del CCD_image[i]['image_data'] #delete image data to minimize size of json file
                
            fig, ax = plt.subplots()
            im=ax.pcolor(im_data)
            ax.set_aspect('equal')
            ax.set_ylim(ax.get_ylim()[::-1])
            fig.colorbar(im,ax=ax,fraction=0.0305)
            plt.tight_layout()
            plt.savefig(filename + ".png")
            cv2.imwrite(filename + "_data.png",im_data.astype(np.uint16))
            np.save(filename + "_data.npy",im_data)
            plt.close(fig)

        else:
            if CCD_image[i].get('id')!=None:
                print('Image ' + CCD_image[i]['id']  + ' has error ' + str(CCD_image[i].get('packet_error')) + ' no image saved')
            else:
                print('Image ' + ' without ID '  + ' has error ' + str(CCD_image[i].get('packet_error')) + ' no image saved')
            
#end loop over channels
        
    filename = out_directory + '/images.json'
    with open(filename, 'w') as outfile:
        print(str('Writing file ' + filename))
        json.dump(CCD_image, outfile, sort_keys = True, indent = 4,
               ensure_ascii = False,cls=JSON_Encoder)
    
    return AllDataSorted, CCD_image


def read_MATS_image(filename,pathdir=''):
    json_file = open(filename,'r')
    CCD_image_data = json.load(json_file)
    json_file.close
            
    for i in range(len(CCD_image_data)):
        CCD_image_data[i]['image'] = np.load(pathdir+str(CCD_image_data[i]['imagefile']) + '_data.npy')

    return CCD_image_data

def read_MATS_packets(filename):
    json_file = open(filename,'r')
    packet_data = json.load(json_file)
    json_file.close
    
    return packet_data
    
def UnsegmentedTimeNanoseconds(coarseTime, fineTime):
    nanos  = coarseTime * NANOS_PER_SECOND
    fine = math.ldexp(fineTime,-16)

    return int(nanos + round(fine*NANOS_PER_SECOND))
