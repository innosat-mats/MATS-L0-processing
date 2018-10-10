#remove import of print function after upgrade to python 3
from __future__ import print_function

import numpy
import binascii
import crc16


##########################################
#Functions used to read MATS payload data. One packet is read starting at
#the bit indicated by pointer
##########################################

#Created 17.02.7 Ole Martin Christensen
#Modified 18.10.5 Franz Kanngiesser

#This function takes in MATS payload data and reads one packet and returns it. 
def read_packet(data, pointer = 0):

    packet = {}
    initial_pointer = pointer
    
    ## Read header information
    block_length = 32
    A = data[pointer:pointer+block_length]
    packet['RAMSES_header_hex'] = binascii.hexlify(A)
    if packet['RAMSES_header_hex'][0:4] != '90eb':
        raise ValueError('Missing RAMSES header')
    pointer = pointer + block_length

    ## Source Packet header
    block_length = 2
    A = data[pointer:pointer+block_length]
    A_bin = [bin(x)[2:].zfill(8) for x in A]
    packet['SPH_packet_id_hex'] = binascii.hexlify(A)
    packet['SPH_version'] = A_bin[0][0:3]
    if packet['SPH_version'] != '000':
        raise ValueError('Version different than 000')
    packet['SPH_type'] = int(A_bin[0][3],2)
    if packet['SPH_type'] == 0:
        packet['SPH_type_mnemonic'] = 'TM'
    elif packet['SPH_type'] == 1:
        packet['SPH_type_mnemonic'] = 'TC'
    else:
        raise ValueError('Invalid type')
    packet['SPH_data_field_header_flag'] = A_bin[0][4]
    if packet['SPH_data_field_header_flag'] != '1':
        raise ValueError('Data field header flag not 1')
    packet['SPH_application_process_id'] = int(A_bin[0][5:] +A_bin[1][1:],2) #should use .join here instead!
    if packet['SPH_application_process_id'] != 100:
        raise ValueError('ApID not 100')
    pointer = pointer + block_length

    ## Packet sqeuence control
    block_length = 2
    A = data[pointer:pointer+block_length]
    A_bin = [bin(x)[2:].zfill(8) for x in A]
    packet['SPH_packet_sequence_control_hex'] = binascii.hexlify(A)
    packet['SPH_grouping_flags'] = A_bin[0][0:2]
    if packet['SPH_grouping_flags'] == '11' or packet['SPH_grouping_flags'] == '01' :
        packet['SPH_continuation_package'] = False
    elif packet['SPH_grouping_flags'] == '10' or packet['SPH_grouping_flags'] == '00':
        packet['SPH_continuation_package'] = True
    packet['SPH_source_sequence_count'] = int(A_bin[0][2:]+A_bin[1][:],2) #should use .join here instead!
    pointer = pointer + block_length

    ## Packet length
    block_length = 2
    A = data[pointer:pointer+block_length]
    A_bin = [bin(x)[2:].zfill(8) for x in A]
    packet['SPH_packet_length_hex'] = binascii.hexlify(A)
    packet['SPH_packet_length'] = int(A_bin[0][:]+A_bin[1][:],2) #should use .join here instead!
    pointer = pointer + block_length

    ## Data field header
    if packet['SPH_type'] == 0:
        data_field_header_length = 9
    elif packet['SPH_type'] == 1:
        raise ValueError('TC packets not implemented yet')
    block_length = data_field_header_length
    A = data[pointer:pointer+block_length]
    A_bin = [bin(x)[2:].zfill(8) for x in A]
    packet['DFH_data_field_header_hex'] = binascii.hexlify(A)
    if A_bin[0][0] != '0' or A_bin[0][4:8] != '0000':
        raise ValueError('Spare bits not set correctly in data field header')
    packet['DFH_TM_source_packet_PUS_version_number'] = A_bin[0][1:4]
    if packet['DFH_TM_source_packet_PUS_version_number']  != '001':
        raise ValueError('TM source packet version not 111')
    packet['DFH_service_type'] = int(A_bin[1][:],2)
    packet['DFH_service_subtype'] = int(A_bin[2][:],2)
    packet['DFH_CUC_time_seconds'] = int("".join(A_bin[3:7]),2)
    packet['DFH_CUC_time_fraction'] = int("".join(A_bin[8:10]),2)
    pointer = pointer + block_length
    
    ## SID (This should be rewritten as SID is not read for certain subtypes)
    block_length = 2
    A = data[pointer:pointer+block_length]
    A_bin = [bin(x)[2:].zfill(8) for x in A]
    SID_hex = binascii.hexlify(A)
    SID = int("".join(A_bin[:]),2)
    pointer = pointer + block_length

    ## Data
    block_length = packet['SPH_packet_length'] - data_field_header_length -2 - 1 # data length = packet lengt - data field header - sid length - 1
    A = data[pointer:pointer+block_length]
    A_bin = [bin(x)[2:].zfill(8) for x in A]
    packet['Source_data_hex'] = binascii.hexlify(A)
    packet['Source_data'] = read_payload_data(packet['SPH_type_mnemonic'],packet['DFH_service_type'],
                                       packet['DFH_service_subtype'],SID,
                                       packet['SPH_continuation_package'],block_length,
                                       packet['Source_data_hex'])[0]
    pointer = pointer + block_length
    packet['Source_data']['SID_hex'] = SID_hex
    packet['Source_data']['SID'] = SID
    

    ## Control bits
    block_length = 2
    A = data[pointer:pointer+block_length]
    A_bin = [bin(x)[2:].zfill(8) for x in A]
    packet['Packet_error_control_hex'] = binascii.hexlify(A)
    pointer = pointer + block_length
    
    packet_data = binascii.hexlify(data[initial_pointer+32:pointer-block_length]) #get binary data for all packet (-RAMSES header, -Packet error control hex)
    crc_dec = crc16.crc16xmodem(packet_data.decode("hex"),65535) #Calculate crc16-CCITT (0xFFFF initialization)
    crc = hex(crc_dec)[2:].zfill(4) #convert to hex, remove 0x from string and add leading zeros
    if packet['Packet_error_control_hex']  != crc:
        raise ValueError('CRC checksum failed')
    
    
    return [packet,pointer]

#Takes in payload data as hex and reads it in the correct format and places in dictionary.
def read_payload_data(packet_type,service_type,service_subtype,sid,cont_package,block_length,payload_data):
    data = {}
    if packet_type == 'TM' and service_type == 3 and service_subtype == 25: #housekeeping data
        data = read_payload_housekeeping_data(payload_data,sid,block_length)
    elif packet_type == 'TM' and service_type == 128 and service_subtype == 25: #CCD data
        data = read_payload_transparent_data(payload_data,sid,cont_package,block_length)
    elif packet_type == 'TM' and service_type == 1 and service_subtype == 1:
        data = read_payload_generic_data(payload_data,sid,block_length) #Generic data (not yet specified)
    elif packet_type == 'TM' and service_type == 1 and service_subtype == 7:
        data = read_payload_generic_data(payload_data,sid,block_length) #Generic data (not yet specified)
    else:
        raise ValueError(['Packets not yet implemented ' +
                          'packet type = ' + str(packet_type) + ' ' +
                          ' service_type = ' + str(service_type) + ' ' + 
                          ' service_subtype = ' + str(service_subtype)])
    return data

#Takes in payload data transfer as hex and reads it as hex.
def read_payload_generic_data(payload_data, sid, block_length_test):
    data = {}
    
    print('Reading generic payload data')    
    data['SID_mnemonic'] = 'generic data'
    data['generic_data_hex'] = payload_data
        
    return [data]

#Takes in payload housekeeping data as hex and reads it in the correct format and places in dictionary. All data is read with
#small-endian.
def read_payload_housekeeping_data(payload_data, sid, block_length_test):
    print('Reading payload housekeeping data')
    data = {}
    
    if sid == 1:
        ## STATUS
        print('Reading STATUS')    
        block_length = 33
        if block_length != block_length_test:
            raise ValueError('Block length and SID does not match ' + str(block_length_test))
        data['SID_mnemonic'] = 'Status'
        data['SPID'] = numpy.fromstring(binascii.unhexlify(payload_data[0:4]),numpy.dtype('<u2'))
        data['SPREV'] = numpy.fromstring(binascii.unhexlify(payload_data[4:6]),numpy.dtype('<u1'))
        data['FPID'] = numpy.fromstring(binascii.unhexlify(payload_data[6:10]),numpy.dtype('<u2'))
        data['FPREV'] = numpy.fromstring(binascii.unhexlify(payload_data[10:12]),numpy.dtype('<u1'))
        data['TS'] = numpy.fromstring(binascii.unhexlify(payload_data[12:20]),numpy.dtype('<u4'))
        data['TSS'] = numpy.fromstring(binascii.unhexlify(payload_data[20:24]),numpy.dtype('<u1'))
        data['MODE'] = numpy.fromstring(binascii.unhexlify(payload_data[24:26]),numpy.dtype('<u1'))
        data['EDACE'] = numpy.fromstring(binascii.unhexlify(payload_data[26:34]),numpy.dtype('<u4'))
        data['EDACCE'] = numpy.fromstring(binascii.unhexlify(payload_data[34:42]),numpy.dtype('<u4'))
        data['EDACN'] = numpy.fromstring(binascii.unhexlify(payload_data[42:50]),numpy.dtype('<u4'))
        data['SPWEOP'] = numpy.fromstring(binascii.unhexlify(payload_data[50:58]),numpy.dtype('<u4'))
        data['SPWEEP'] = numpy.fromstring(binascii.unhexlify(payload_data[58:66]),numpy.dtype('<u4'))


    elif sid == 10:
        #Heater module housekeeping
        print('Reading Heater housekeeping')    
        block_length = 48#64
        if block_length != block_length_test:
            raise ValueError('Block length and SID does not match' + str(block_length_test))    
        data['SID_mnemonic'] = 'Heater module housekeeping data'
        data['HTR1A'] = numpy.fromstring(binascii.unhexlify(payload_data[0:4]),numpy.dtype('<u2'))
        data['HTR1B'] = numpy.fromstring(binascii.unhexlify(payload_data[4:8]),numpy.dtype('<u2'))
        data['HTR1OD'] = numpy.fromstring(binascii.unhexlify(payload_data[8:12]),numpy.dtype('<u2'))
        data['HTR2A'] = numpy.fromstring(binascii.unhexlify(payload_data[12:16]),numpy.dtype('<u2'))
        data['HTR2B'] = numpy.fromstring(binascii.unhexlify(payload_data[16:20]),numpy.dtype('<u2'))
        data['HTR2OD'] = numpy.fromstring(binascii.unhexlify(payload_data[20:24]),numpy.dtype('<u2'))
        data['HTR3A'] = numpy.fromstring(binascii.unhexlify(payload_data[24:28]),numpy.dtype('<u2'))
        data['HTR3B'] = numpy.fromstring(binascii.unhexlify(payload_data[28:32]),numpy.dtype('<u2'))
        data['HTR3OD'] = numpy.fromstring(binascii.unhexlify(payload_data[32:36]),numpy.dtype('<u2'))
        data['HTR4A'] = numpy.fromstring(binascii.unhexlify(payload_data[36:40]),numpy.dtype('<u2'))
        data['HTR4B'] = numpy.fromstring(binascii.unhexlify(payload_data[40:44]),numpy.dtype('<u2'))
        data['HTR4OD'] = numpy.fromstring(binascii.unhexlify(payload_data[44:48]),numpy.dtype('<u2'))
        data['HTR5A'] = numpy.fromstring(binascii.unhexlify(payload_data[48:52]),numpy.dtype('<u2'))
        data['HTR5B'] = numpy.fromstring(binascii.unhexlify(payload_data[52:56]),numpy.dtype('<u2'))
        data['HTR5OD'] = numpy.fromstring(binascii.unhexlify(payload_data[56:60]),numpy.dtype('<u2'))
        data['HTR6A'] = numpy.fromstring(binascii.unhexlify(payload_data[60:64]),numpy.dtype('<u2'))
        data['HTR6B'] = numpy.fromstring(binascii.unhexlify(payload_data[64:68]),numpy.dtype('<u2'))
        data['HTR6OD'] = numpy.fromstring(binascii.unhexlify(payload_data[68:72]),numpy.dtype('<u2'))
        data['HTR7A'] = numpy.fromstring(binascii.unhexlify(payload_data[72:76]),numpy.dtype('<u2'))
        data['HTR7B'] = numpy.fromstring(binascii.unhexlify(payload_data[76:80]),numpy.dtype('<u2'))
        data['HTR7OD'] = numpy.fromstring(binascii.unhexlify(payload_data[80:84]),numpy.dtype('<u2'))
        data['HTR8A'] = numpy.fromstring(binascii.unhexlify(payload_data[84:88]),numpy.dtype('<u2'))
        data['HTR8B'] = numpy.fromstring(binascii.unhexlify(payload_data[88:92]),numpy.dtype('<u2'))
        data['HTR8OD'] = numpy.fromstring(binascii.unhexlify(payload_data[92:96]),numpy.dtype('<u2'))
        
    
    elif sid == 20:
        #Power module housekeeping
        print('Reading Power housekeeping')    
        block_length = 18
        if block_length != block_length_test:
            raise ValueError('Block length and SID does not match' + str(block_length_test))    
        data['SID_mnemonic'] = 'Power module housekeeping data'
        data['PWRT'] = numpy.fromstring(binascii.unhexlify(payload_data[0:4]),numpy.dtype('<u2'))
        data['PWRP32V'] = numpy.fromstring(binascii.unhexlify(payload_data[4:8]),numpy.dtype('<u2'))
        data['PWRP32C'] = numpy.fromstring(binascii.unhexlify(payload_data[8:12]),numpy.dtype('<u2'))
        data['PWRP16V'] = numpy.fromstring(binascii.unhexlify(payload_data[12:16]),numpy.dtype('<u2'))
        data['PWRP16C'] = numpy.fromstring(binascii.unhexlify(payload_data[16:20]),numpy.dtype('<u2'))
        data['PWRM16V'] = numpy.fromstring(binascii.unhexlify(payload_data[20:24]),numpy.dtype('<u2'))
        data['PWRM16C'] = numpy.fromstring(binascii.unhexlify(payload_data[24:28]),numpy.dtype('<u2'))
        data['PWRP3V3'] = numpy.fromstring(binascii.unhexlify(payload_data[28:32]),numpy.dtype('<u2'))
        data['PWRP3C3'] = numpy.fromstring(binascii.unhexlify(payload_data[32:36]),numpy.dtype('<u2'))

    elif sid == 30:
        #CPRUA
        print('Reading CPRUA housekeeping')    
        block_length = 32#9
        if block_length != block_length_test:
            raise ValueError('Block length and SID does not match' + str(block_length_test))    
        data['SID_mnemonic'] = 'CPRUA module housekeeping data'
        data['VGATE0'] = numpy.fromstring(binascii.unhexlify(payload_data[0:4]),numpy.dtype('<u2'))
        data['VSUBS0'] = numpy.fromstring(binascii.unhexlify(payload_data[4:8]),numpy.dtype('<u2'))
        data['VRD0'] = numpy.fromstring(binascii.unhexlify(payload_data[8:12]),numpy.dtype('<u2'))
        data['VOD0'] = numpy.fromstring(binascii.unhexlify(payload_data[12:16]),numpy.dtype('<u2'))
        data['VGATE1'] = numpy.fromstring(binascii.unhexlify(payload_data[16:20]),numpy.dtype('<u2'))
        data['VSUBS1'] = numpy.fromstring(binascii.unhexlify(payload_data[20:24]),numpy.dtype('<u2'))
        data['VRD1'] = numpy.fromstring(binascii.unhexlify(payload_data[24:28]),numpy.dtype('<u2'))
        data['VOD1'] = numpy.fromstring(binascii.unhexlify(payload_data[28:32]),numpy.dtype('<u2'))
        data['VGATE2'] = numpy.fromstring(binascii.unhexlify(payload_data[32:36]),numpy.dtype('<u2'))
        data['VSUBS2'] = numpy.fromstring(binascii.unhexlify(payload_data[36:40]),numpy.dtype('<u2'))
        data['VRD2'] = numpy.fromstring(binascii.unhexlify(payload_data[40:44]),numpy.dtype('<u2'))
        data['VOD2'] = numpy.fromstring(binascii.unhexlify(payload_data[44:48]),numpy.dtype('<u2'))
        data['VGATE3'] = numpy.fromstring(binascii.unhexlify(payload_data[48:52]),numpy.dtype('<u2'))
        data['VSUBS3'] = numpy.fromstring(binascii.unhexlify(payload_data[52:56]),numpy.dtype('<u2'))
        data['VRD3'] = numpy.fromstring(binascii.unhexlify(payload_data[56:60]),numpy.dtype('<u2'))
        data['VOD3'] = numpy.fromstring(binascii.unhexlify(payload_data[60:64]),numpy.dtype('<u2'))        
            
    elif sid == 31:
        #CPRUB
        print('Reading CPRUB housekeeping')    
        block_length = 32#9
        if block_length != block_length_test:
            raise ValueError('Block length and SID does not match' + str(block_length_test))    
        data['SID_mnemonic'] = 'CPRUB module housekeeping data'
        data['VGATE0'] = numpy.fromstring(binascii.unhexlify(payload_data[0:4]),numpy.dtype('<u2'))
        data['VSUBS0'] = numpy.fromstring(binascii.unhexlify(payload_data[4:8]),numpy.dtype('<u2'))
        data['VRD0'] = numpy.fromstring(binascii.unhexlify(payload_data[8:12]),numpy.dtype('<u2'))
        data['VOD0'] = numpy.fromstring(binascii.unhexlify(payload_data[12:16]),numpy.dtype('<u2'))
        data['VGATE1'] = numpy.fromstring(binascii.unhexlify(payload_data[16:20]),numpy.dtype('<u2'))
        data['VSUBS1'] = numpy.fromstring(binascii.unhexlify(payload_data[20:24]),numpy.dtype('<u2'))
        data['VRD1'] = numpy.fromstring(binascii.unhexlify(payload_data[24:28]),numpy.dtype('<u2'))
        data['VOD1'] = numpy.fromstring(binascii.unhexlify(payload_data[28:32]),numpy.dtype('<u2'))
        data['VGATE2'] = numpy.fromstring(binascii.unhexlify(payload_data[32:36]),numpy.dtype('<u2'))
        data['VSUBS2'] = numpy.fromstring(binascii.unhexlify(payload_data[36:40]),numpy.dtype('<u2'))
        data['VRD2'] = numpy.fromstring(binascii.unhexlify(payload_data[40:44]),numpy.dtype('<u2'))
        data['VOD2'] = numpy.fromstring(binascii.unhexlify(payload_data[44:48]),numpy.dtype('<u2'))
        data['VGATE3'] = numpy.fromstring(binascii.unhexlify(payload_data[48:52]),numpy.dtype('<u2'))
        data['VSUBS3'] = numpy.fromstring(binascii.unhexlify(payload_data[52:56]),numpy.dtype('<u2'))
        data['VRD3'] = numpy.fromstring(binascii.unhexlify(payload_data[56:60]),numpy.dtype('<u2'))
        data['VOD3'] = numpy.fromstring(binascii.unhexlify(payload_data[60:64]),numpy.dtype('<u2'))        

    else:
        print('SID not implemented')
        
    return [data]
    
#Takes in payload transparent data transfer as hex and reads it in the correct 
#format and places in dictionary. All data is read with
#small-endian. Not all SIDs are implemented
def read_payload_transparent_data(payload_data, sid, cont_packet, block_length_test):
    #print 'Reading transparent payload data'
    data = {}
    if sid == 21 or 22 or 23 or 24 or 25 or 26 or 27:#actually called rid, not sid
        ## CCD data
        #Check if packet is the start or a continuation of previous packages
        if cont_packet == False:
            print('Reading CCD data')    
            data['SID_mnemonic'] = ['CCD data channel ' + str(sid-20)]
            data['CCDSEL'] = numpy.fromstring(binascii.unhexlify(payload_data[0:2]),numpy.dtype('<u1'))
            data['EXPTS'] = numpy.fromstring(binascii.unhexlify(payload_data[2:10]),numpy.dtype('<u4'))
            data['EXPTSS'] = numpy.fromstring(binascii.unhexlify(payload_data[10:14]),numpy.dtype('<u2'))
            data['WDW'] = numpy.fromstring(binascii.unhexlify(payload_data[14:16]),numpy.dtype('<u1'))
            data['WDWOV'] = numpy.fromstring(binascii.unhexlify(payload_data[16:20]),numpy.dtype('<u2'))        
            data['JPEGQ'] = numpy.fromstring(binascii.unhexlify(payload_data[20:22]),numpy.dtype('<u1'))
            data['TEXPMS'] = numpy.fromstring(binascii.unhexlify(payload_data[22:30]),numpy.dtype('<u4'))
            data['RBIN'] = numpy.fromstring(binascii.unhexlify(payload_data[30:32]),numpy.dtype('<u1'))
            data['CBIN'] = numpy.fromstring(binascii.unhexlify(payload_data[32:34]),numpy.dtype('<u1'))
            data['GAIN'] = numpy.fromstring(binascii.unhexlify(payload_data[34:38]),numpy.dtype('<u2'))
            data['GAINOV'] = numpy.fromstring(binascii.unhexlify(payload_data[38:42]),numpy.dtype('<u2'))
            data['NFLUSH'] = numpy.fromstring(binascii.unhexlify(payload_data[42:46]),numpy.dtype('<u2'))
            data['NRSKIP'] = numpy.fromstring(binascii.unhexlify(payload_data[46:50]),numpy.dtype('<u2'))
            data['NRBIN'] = numpy.fromstring(binascii.unhexlify(payload_data[50:54]),numpy.dtype('<u2'))
            data['NROW'] = numpy.fromstring(binascii.unhexlify(payload_data[54:58]),numpy.dtype('<u2'))
            data['NCSKIP'] = numpy.fromstring(binascii.unhexlify(payload_data[58:62]),numpy.dtype('<u2'))
            data['NCBIN'] = numpy.fromstring(binascii.unhexlify(payload_data[62:66]),numpy.dtype('<u2'))
            data['NCOL'] = numpy.fromstring(binascii.unhexlify(payload_data[66:70]),numpy.dtype('<u2'))
            data['NBC'] = numpy.fromstring(binascii.unhexlify(payload_data[70:74]),numpy.dtype('<u2'))
            data['BC'] = numpy.fromstring(binascii.unhexlify(payload_data[74:74+int(data['NBC'])*2]),numpy.dtype('<u2'))
            data['IMG'] = payload_data[74+int(data['NBC'])*2:]        
        else: #if continuation
            data['SID_mnemonic'] = ['CCD data channel ' + str(sid-20)]
            data['IMG'] = payload_data[:]        

    elif sid == 30:
        #Photometer data
        print('Reading Photometer data')    
        block_length = 54#was 13 before without any error message shown
        if block_length != block_length_test:
            raise ValueError('Block length and SID does not match')    
        data['SID_mnemonic'] = 'Photometer data'    
        print('Reading photometer data')    
        data['SID_mnemonic'] = ['Photometer data']
        data['ExpTS'] = numpy.fromstring(binascii.unhexlify(payload_data[0:8]),numpy.dtype('<u4'))
        data['ExpTSS'] = numpy.fromstring(binascii.unhexlify(payload_data[8:12]),numpy.dtype('<u2'))
        data['PM1A'] = numpy.fromstring(binascii.unhexlify(payload_data[12:20]),numpy.dtype('<u4'))
        data['PM1ACntr'] = numpy.fromstring(binascii.unhexlify(payload_data[20:28]),numpy.dtype('<u4'))
        data['PM1B'] = numpy.fromstring(binascii.unhexlify(payload_data[28:36]),numpy.dtype('<u4'))
        data['PM1BCntr'] = numpy.fromstring(binascii.unhexlify(payload_data[36:44]),numpy.dtype('<u4'))
        data['PM1S'] = numpy.fromstring(binascii.unhexlify(payload_data[44:52]),numpy.dtype('<u4'))
        data['PM1SCntr'] = numpy.fromstring(binascii.unhexlify(payload_data[52:60]),numpy.dtype('<u4'))
        data['PM2A'] = numpy.fromstring(binascii.unhexlify(payload_data[60:68]),numpy.dtype('<u4'))
        data['PM2ACntr'] = numpy.fromstring(binascii.unhexlify(payload_data[68:76]),numpy.dtype('<u4'))
        data['PM2B'] = numpy.fromstring(binascii.unhexlify(payload_data[76:84]),numpy.dtype('<u4'))
        data['PM2BCntr'] = numpy.fromstring(binascii.unhexlify(payload_data[84:92]),numpy.dtype('<u4'))
        data['PM2S'] = numpy.fromstring(binascii.unhexlify(payload_data[92:100]),numpy.dtype('<u4'))
        data['PM2SCntr'] = numpy.fromstring(binascii.unhexlify(payload_data[100:108]),numpy.dtype('<u4'))

        
    else:
        print('SID not implemented')
        
    return [data]
