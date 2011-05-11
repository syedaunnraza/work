#!/usr/bin/env python

import sys
import matplotlib.pyplot as plt
import numpy as np

def draw_histograms(intervals, dest_prefix, time, cfg):
    same = []
    diff = []
    for start,end,common in intervals:
        if common:
            same.append(end-start)
        else:
            diff.append(end-start)
            
    if len(diff) > 0:
        fig = plt.figure()
        ax = fig.add_subplot(111)
        buckets = 50
        if (len(diff) == 1):
            buckets = 5
        n, bins, patches = plt.hist(diff, buckets, normed=0, facecolor='green', alpha=0.75)
        plt.xlabel('Divergence Length (#Instructions)')
        plt.ylabel(r'$\mathrm{Frequency}$')
        if time != -1:
            ax.annotate('Total Instructions: ' + str(intervals[-1][1]) + ', Total Time: ' + str(time) + ' secs.', 
                        (max(diff)*1/6,len(diff)*4/5), xytext=None, xycoords='data',
                        textcoords='data', arrowprops=None)
        else:
            ax.annotate('Total Instructions: ' + str(intervals[-1][1]) + '.', 
                        (max(diff)*2/6,len(diff)*4/5), xytext=None, xycoords='data',
                        textcoords='data', arrowprops=None)
        if cfg:
            plt.title(r'$\mathrm{Histogram\ of\ Control\ Flow\ Divergence}\ $')
        else:
            plt.title(r'$\mathrm{Histogram\ of\ Instruction\ Side-Effect\ Divergence}\ $')
        plt.axis([max(0, min(diff)-2), max(1, max(diff)), 0, len(diff)])
        plt.grid(True)
        if cfg:
            fig.savefig(dest_prefix + "cfg_hist_div.pdf", dpi=10)
        else:
            fig.savefig(dest_prefix + "ins_hist_div.pdf", dpi=10)
        
    if (len(same) > 0):
        fig = plt.figure()
        ax = fig.add_subplot(111)
        buckets = 50
        if (len(same) == 1):
            buckets = 5
        n, bins, patches = plt.hist(same, buckets, normed=0, facecolor='green', alpha=0.75)
        plt.xlabel('Identical Sub-Trace Length (#Instructions)')
        plt.ylabel(r'$\mathrm{Frequency}$')
        if time != -1:
            ax.annotate('Total Instructions: ' + str(intervals[-1][1]) + ', Total Time: ' + str(time) + ' secs.', 
                        (max(same)*1/6,len(same)*4/5), xytext=None, xycoords='data',
                        textcoords='data', arrowprops=None)
        else:
            ax.annotate('Total Instructions: ' + str(intervals[-1][1]) + '.', 
                        (max(same)*2/6,len(same)*4/5), xytext=None, xycoords='data',
                        textcoords='data', arrowprops=None)
        if cfg:
            plt.title(r'$\mathrm{Histogram\ of\ Control\ Flow\ Determinism}\ $')
        else:
            plt.title(r'$\mathrm{Histogram\ of\ Instruction\ Side-Effect\ Determinism}\ $')
        plt.axis([max(0, min(same)-2), max(1, max(same)), 0, len(same)])
        plt.grid(True)
        if cfg:
            fig.savefig(dest_prefix + "cfg_hist_same.pdf", dpi=10)
        else:
            fig.savefig(dest_prefix + "ins_hist_same.pdf", dpi=10)

    return


# time == -1 if timing information not available
def draw_trace(intervals, dest_prefix, time, cfg):
    fig = plt.figure()
    ax = fig.add_subplot(111)
    
    common_intervals = []
    diff_intervals = []
    total_common = 0
    total_diff = 0
    for (start, end, common) in intervals:
        if common:
            total_common += (end-start)
            common_intervals.append((start, end-start))
        else:
            total_diff += (end-start)
            diff_intervals.append((start,end-start))
                    
    ax.broken_barh(common_intervals, (10, 10), facecolors='blue')
    ax.broken_barh(diff_intervals, (35, 10), facecolors='green')

    ax.set_ylim(0,50)
    ax.set_xlim(0, intervals[-1][1])
    ax.set_xlabel(r'$\mathrm{Instructions\ Executed}$')
    ax.set_yticks([15,40])
    ax.set_yticklabels([r'$\mathrm{Same}$', '$\mathrm{Diff}$'])
    ax.grid(True)

    if cfg:
        ax.set_title(r'$\mathrm{Control\ Flow\ Divergence}$')
    else:
        ax.set_title(r'$\mathrm{Instruction Side-Effect\ Divergence}$')
    
    diff_percent = 100.0*float(total_diff)/(total_diff+total_common)
    diff_percent = "%.2f" % diff_percent 
    threshold = intervals[-1][1] / 100

    if (time != -1):
        ax.annotate('Diff: ' + diff_percent + '%, Time: ' + str(time) + ' seconds.', 
                    (threshold*30,30), xytext=None, xycoords='data',
                    textcoords='data', arrowprops=None)
    else:
        ax.annotate('Diff: ' + diff_percent + '%, #Ins: ' + str(intervals[-1][1]), 
                    (threshold*20,30), xytext=None, xycoords='data',
                    textcoords='data', arrowprops=None)
    if cfg:
        fig.savefig(dest_prefix + "cfg_trace.pdf", dpi=300)
    else:
        fig.savefig(dest_prefix + "ins_trace.pdf", dpi=300)

    print '\tDone with drawing trace'
    draw_histograms(intervals, dest_prefix, time, cfg)
    return

def ins_visualize_files(file1, file2):
    handle1 = open(file1)
    handle2 = open(file2)

    line1 = handle1.readline()
    line2 = handle2.readline()
    
    num_ins = 0
    intervals = []

    while(line1 != '' and line2 != ''):
        if (line1[0:2] != '0x'):
            line1 = handle1.readline()
            continue

        if (line2[0:2] != '0x'):
            line2 = handle2.readline()
            continue

        if line1 != line2:
            new_interval = (num_ins, num_ins+1, False)
        else:
            new_interval = (num_ins, num_ins+1, True)

        num_ins += 1

        if (len(intervals) > 0):
            startP, endP, isCommonP = intervals[-1]
            startN, endN, isCommonN = new_interval
            if (isCommonP == isCommonN and endP == startN):
                intervals[-1] = (startP, endN, isCommonN)
            else:
                intervals.append(new_interval)
        else:
          intervals.append(new_interval)

        line1 = handle1.readline()
        line2 = handle2.readline()

    handle1.close()
    handle2.close()
    return intervals

def main(args):
    if len(args) != 3:
        print 'usage: binary {file1} {file2} {figures_directory}'
        return
    else:
        print 'starting instruction side-effect analysis'
        intervals_ins = ins_visualize_files(args[0], args[1])
        if (len(intervals_ins) < 100):
            print intervals_ins
        else:
            print 'not printing intervals because they are too numerous (' + str(len(intervals_ins)) + ')'
        draw_trace(intervals_ins, args[2], -1, False)
        return

if __name__ == "__main__":
    main(sys.argv[1:])
    
