#!/usr/bin/python
#main file to test MATS processing

import sys, getopt
from read_racdirectory import read_racdirectory


def main(argv):
    in_directory = ''
    out_directory = 'out'
    try:
        opts, args = getopt.getopt(argv,"hi:o:",["ifile=","ofile="])
    except getopt.GetoptError:
        print 'rac_extract.py -i <inputdir> -o <inputdir>'
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print 'rac_extract.py -i <inputdir> -o <inputdir>'
            sys.exit()
        elif opt in ("-i", "--idir"):
            in_directory = arg
        elif opt in ("-o", "--odir"):
            out_directory = arg

    if in_directory == '':
		print('Input directory not specificed (use -i)')
		sys.exit()
    a, b = read_racdirectory(in_directory,out_directory)

if __name__ == '__main__':

    main(sys.argv[1:])

