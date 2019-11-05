#!/usr/bin/python
#main file to test MATS processing

import sys, getopt
from read_racdirectory import read_racdirectory
import os

def main(argv):
    in_directory = ''
    out_directory = ''
    try:
        opts, args = getopt.getopt(argv,"hi:o:",["ifile=","ofile="])
    except getopt.GetoptError:
        print 'rac_extract.py -i <inputdir/file> -o <outputdir>'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print 'rac_extract.py -i <inputdir/file> -o <outputdir>'
            sys.exit()
        elif opt in ("-i", "--idir"):
            in_directory = arg
        elif opt in ("-o", "--odir"):
            out_directory = arg

    if in_directory == '':
		print('Input directory not specificed (use -i)')
		sys.exit()
    if out_directory == '':
        if os.path.isfile(in_directory):
              out_directory = in_directory[:-4]
        else:
              out_directory = in_directory + '_out'
          
    a, b = read_racdirectory(in_directory,out_directory)

if __name__ == '__main__':

    main(sys.argv[1:])

