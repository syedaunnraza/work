#!/usr/bin/env python

import sys
import math
from time import gmtime, strftime, localtime
import random

def get_time():
    return '\t'+ strftime("[%d %b %Y %H:%M:%S]", localtime())

def count_lines(fileName):
    handle = open(fileName)
    count = 0
    line = 'ignore value'
    while(line != ''):
        line = handle.readline()
        count += 1
    handle.close()
    return count

def find_good_candidate_pc(file1, file2, 
                           num_lines, 
                           MAX_PCS_SIZE, 
                           start_percent,
                           end_percent):

    print '\t' + get_time() + ' picking random pcs (' + str(start_percent) + '-' + str(end_percent) + ')'
    handle1 = open(file1)
    handle2 = open(file2)

    candidate_pcs = []
    
    one_percent = num_lines / 100
    current_lines = 0

    while(True):
        line1 = handle1.readline()
        line2 = handle2.readline()
        current_lines += 1
        current_percent = int(current_lines / one_percent) 
        
        if (current_percent < start_percent):
            continue
        if (current_percent >= end_percent):
            break

        # we are current in the target range [start_percent, end_percent)
        if line1[0:2] == '0x':
            pc1 = line1[2:10]
            if (pc1 not in candidate_pcs
                and len(candidate_pcs) < MAX_PCS_SIZE
                and random.random() < 0.1):
                candidate_pcs.append(pc1)
                
        if line2[0:2] == '0x':
            pc2 = line2[2:10]
            if (pc2 not in candidate_pcs
                and len(candidate_pcs) < MAX_PCS_SIZE
                and random.random() < 0.1):
                candidate_pcs.append(pc2)
    
    handle1.close()
    handle2.close()
    
    ######################################################################
    print '\t' + get_time() + ' rescanning frequencies [#pcs = ' + str(len(candidate_pcs)) +'] for (' + str(start_percent) + '-' + str(end_percent) + ')'

    handle1 = open(file1)
    handle2 = open(file2)

    freq = dict()
    for pc in candidate_pcs:
        freq[pc] = 0,0

    for i in range(current_lines):
        line1 = handle1.readline()
        line2 = handle2.readline()
        if line1[0:2] == '0x':
            pc1 = line1[2:10]
            if pc1 in candidate_pcs:
                old1, old2 = freq[pc1]
                freq[pc1] = old1+1, old2
        if line2[0:2] == '0x':
            pc2 = line2[2:10]
            if pc2 in candidate_pcs:
                old1, old2 = freq[pc2]
                freq[pc2] = old1, old2+1
    
    handle1.close()
    handle2.close()

    ######################################################################
    print '\t' + get_time() + ' picking best pc (' + str(start_percent) + '-' + str(end_percent) + ')'
    best_pc = -1
    best_frequency = num_lines + 1
    for pc in candidate_pcs:
        f1, f2 = freq[pc]
        if f1 == f2 and f1 < best_frequency:
            best_pc = pc
            best_frequency = f1
    return best_pc, best_frequency
    
def main(args):
    if len(args) != 4:
        print 'usage: binary {file1} {file2} {destination file} {CACHE_SIZE}'
        return
    else:
        count1 = count_lines(args[0])
        print get_time() + ' file 1 has ' + str(count1) + ' lines'
        count2 = count_lines(args[1])
        print get_time() + ' file 2 has ' + str(count2) + ' lines'

        num_lines = min(count1, count2)
        CACHE_SIZE = int(args[3])
        
        write_handle = open(args[2], 'w')

        percents = [(8,12), (18,22), (28,32), (38, 42), (48, 52), (58, 62),
                    (68,72), (78, 82), (89, 92), (95,100)]
        for start_percent, end_percent in percents:
            print get_time() + ' finding pc for range ' + str(start_percent) + '-' + str(end_percent)
            best_pc, best_count = find_good_candidate_pc(args[0], args[1], 
                                                         num_lines, 
                                                         CACHE_SIZE, 
                                                         start_percent,
                                                         end_percent)
            if (best_pc == -1):
                print get_time() + ' found no pc for range ' + str(start_percent) + '-' + str(end_percent)
            else:
                print get_time() + ' found pc for range ' + str(start_percent) + '-' + str(end_percent)
                write_handle.write('percent <' + str(int(0.5*start_percent + 0.5*end_percent)) + '> ' +
                                   'pc <' + str(best_pc) + '> ' + 
                                   'count <' + str(best_count) + '>\n')
        write_handle.close()
        print get_time() + ' done'
        return

if __name__ == "__main__":
    main(sys.argv[1:])
    
