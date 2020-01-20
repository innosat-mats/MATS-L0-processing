#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#################################
#converts 12bit jpeg files into pnm files and reads the values
#################################
#previously included in imagereader.py

import subprocess
import numpy as np

#Call external application for conversion of 12 bit jpeg
def read12bit_jpeg(fileName):
        djpegLocation = './djpeg'
        outputFile = fileName + ".pnm"
    
        batcmd = djpegLocation + ' -pnm -outfile ' +outputFile + ' ' + fileName #call jpeg decompression executable            
        imagedata = subprocess.check_output(batcmd,shell=True) #load imagedata including header

        with open(outputFile,'rb') as f:
            imagedata=f.read()
                
        newLine=b'\n'
        imagedata=imagedata.split(newLine,3)    #split into magicnumber, shape, maxval and data

        imsize = imagedata[1].split() #size of image in height/width
        imsize = [int(i) for i in imsize]
        imsize.reverse() #flip size to get width/heigth
        
        im = np.frombuffer(imagedata[3], dtype=np.uint16) #read image data
        
        im = im.reshape(imsize) #reshape image
        return im
