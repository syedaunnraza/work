#!/usr/bin/env python

import sys
import matplotlib.pyplot as plt
import numpy as np
from time import gmtime, strftime, localtime

def get_time():
    return '\t'+ strftime("[%d %b %Y %H:%M:%S]", localtime())

CONFLICT = 0
ONLY_ME  = 1
SAME     = 2

COLORS = ['red', 'blue', 'green']

def draw_trace(intervals1, intervals2, dest_prefix):
    fig = plt.figure()
    ax = fig.add_subplot(111)
    
    points1 = []
    colors1 = []
    for start, end, type in intervals1:
        points1.append((start, end-start))
        colors1.append(COLORS[type])

    points2 = []
    colors2 = []
    for start, end, type in intervals2:
        points2.append((start, end-start))
        colors2.append(COLORS[type])
                    
    ax.broken_barh(points1, (10, 10), facecolors=colors1)
    ax.broken_barh(points2, (35, 10), facecolors=colors2)
    
    ax.set_ylim(0,50)
    ax.set_xlim(0, max(intervals1[-1][1], intervals2[-1][1]))
    ax.set_xlabel(r'$\mathrm{Instruction\ Chunks}$')
    ax.set_yticks([15,40])
    ax.set_yticklabels([r'$\mathrm{Instance\ 1}$', '$\mathrm{Instance\ 2}$'])
    ax.grid(True)
    ax.set_title(r'$\mathrm{Control\ Flow\ Divergence}$')
    
    fig.savefig(dest_prefix, dpi=300)
    

    return

def compute_diff(diff_file, destination_folder):
    handle = open(diff_file)
    line = handle.readline()
    
    A_intervals = []
    B_intervals = []

    index = 0

    conflicts = 0
    same = 0
    onlyA = 0
    onlyB = 0

    while (line != ''):
        A_new_interval = None
        B_new_interval = None
        
        if line.find('|') != -1:
            A_new_interval = (index, index+1, CONFLICT)
            B_new_interval = (index, index+1, CONFLICT)
            conflicts += 1
        elif line.find('<') != -1:
            A_new_interval = (index, index+1, ONLY_ME)
            onlyA += 1
        elif line.find('>') != -1:
            B_new_interval = (index, index+1, ONLY_ME)
            onlyB += 1
        else:
            A_new_interval = (index, index+1, SAME)
            B_new_interval = (index, index+1, SAME)
            same += 1
        if (A_new_interval != None):
            if(len(A_intervals) > 0):
                startP, endP, typeP = A_intervals[-1]
                startN, endN, typeN = A_new_interval
                if (typeP == typeN and endP == startN):
                    A_intervals[-1] = startP, endN, typeP
                else:
                    A_intervals.append(A_new_interval)
            else:
                A_intervals.append(A_new_interval)

        if (B_new_interval != None):
            if(len(B_intervals) > 0):
                startP, endP, typeP = B_intervals[-1]
                startN, endN, typeN = B_new_interval
                if (typeP == typeN and endP == startN):
                    B_intervals[-1] = startP, endN, typeP
                else:
                    B_intervals.append(B_new_interval)
            else:
                B_intervals.append(B_new_interval)
                
        line = handle.readline()
        index += 1

    handle.close()

    print get_time() + ' preliminary analysis results:'
    print '\t\t total lines: ' + str(index)
    print '\t\t total conflicts: ' + str(conflicts)
    print '\t\t total only in A: ' + str(onlyA)
    print '\t\t total only in B: ' + str(onlyB)
    print '\t\t total same: ' + str(same)
    
    same_percent = 100.0*float(same)/float(index)
    same_percent = "%.2f" % same_percent
    conflict_percent = 100.0*float(conflicts)/float(index)
    conflict_percent = "%.2f" % conflict_percent
    print
    print '\t\t same %age = ' + str(same_percent) + ' percent'
    print '\t\t conflict %age = ' +  str(conflict_percent) + ' percent'

    return A_intervals, B_intervals

def main(args):
    if len(args) != 2:
        print 'usage: binary {diff_file} {figures_file}'
        return
    else:
        print get_time() + ' starting analysis of diff file'
        intervals1, intervals2 = compute_diff(args[0], args[1])

        print get_time() + ' starting visualization of diff file'
        draw_trace(intervals1, intervals2, args[1])

        print get_time() + ' done'
        return
    
if __name__ == "__main__":
    main(sys.argv[1:])
    
