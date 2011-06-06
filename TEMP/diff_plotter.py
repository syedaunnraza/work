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

def is_skewed(n):
    max_y = max(n)
    min_y = max_y
    for val in n:
        if val <= 1:
            continue
        if val < min_y:
            min_y = val

    if (max_y > 100*min_y):
        return True, 100*min_y
    else:
        return False, 0

def draw_histograms(intervals1, intervals2, dest_prefix):
    same = []
    diff = []
    cfg_diff = []

    for start, end, type in intervals1:
        if type == SAME:
            same.append(end-start)
        elif type == CONFLICT:
            diff.append(end-start)
        else:
            cfg_diff.append(end-start)

    for start, end, type in intervals2:
        if type == ONLY_ME:
            cfg_diff.append(end-start)
    
    draw_hist_same(same, intervals1[-1][1], dest_prefix + 'hist_same.pdf')
    draw_hist_same_truncated(same, intervals1[-1][1], dest_prefix + 'hist_same_truncated.pdf')

    draw_hist_diff(diff, intervals1[-1][1], dest_prefix + 'hist_diff.pdf')
    draw_hist_diff_truncated(diff, intervals1[-1][1], dest_prefix + 'hist_diff_truncated.pdf')

    draw_hist_cfgdiff(cfg_diff, intervals1[-1][1], dest_prefix + 'hist_cfgdiff.pdf')
    draw_hist_cfgdiff_truncated(cfg_diff, intervals1[-1][1], dest_prefix + 'hist_cfgdiff_truncated.pdf')
    
    return

def draw_hist_same(same, total_instructions, dest):
    if len(same) > 0:
        fig = plt.figure()
        ax = fig.add_subplot(111)
        buckets = 50
        if (len(same) == 1):
            buckets = 5
        n, bins, patches = plt.hist(same, buckets, normed=0, facecolor='green', alpha=0.6)
        plt.xlabel(r'$\mathrm{Identical\ Subtrace\ Lengths\ (Instructions)}\ $')
        plt.ylabel(r'$\mathrm{Frequency}$')

        string_title = r'$\mathrm{Total\ Instructions:\ ' + str(total_instructions) + '.\ Longest\ Sequence:\ ' + str(max(same)) + '.}\ $'        
        ax.annotate(string_title, 
                    (0.16, 0.75), xytext=None, xycoords='data',
                    textcoords='axes fraction', arrowprops=None)
        plt.title(r'$\mathrm{Histogram\ of\ Instruction\ Level\ Determinism}\ $')
        plt.axis([max(0, min(same)-2), max(1, max(same)), 0, len(same)])
        plt.grid(True)
        fig.savefig(dest, dpi=300)
    return

def draw_hist_diff(diff, total_instructions, dest):
    if len(diff) > 0:
        fig = plt.figure()
        ax = fig.add_subplot(111)
        buckets = 50
        if (len(diff) == 1):
            buckets = 5
        n, bins, patches = plt.hist(diff, buckets, normed=0, facecolor='red', alpha=0.6)
        plt.xlabel(r'$\mathrm{Conflicting\ Subtrace\ Lengths\ (Instructions)}\ $')
        plt.ylabel(r'$\mathrm{Frequency}$')
        string_title = r'$\mathrm{Total\ Instructions:\ ' + str(total_instructions) + '.\ Longest\ Sequence:\ ' + str(max(diff)) + '.}\ $'        
        ax.annotate(string_title, 
                    (0.20, 0.75), xytext=None, xycoords='data',
                    textcoords='axes fraction', arrowprops=None)
        plt.title(r'$\mathrm{Histogram\ of\ Instruction\ Level\ Nondeterminism}\ $')
        plt.axis([max(0, min(diff)-2), max(1, max(diff)), 0, len(diff)])
        plt.grid(True)
        fig.savefig(dest, dpi=300)
    return

def draw_hist_cfgdiff(cfg_diff, total_instructions, dest):
    if len(cfg_diff) > 0:
        fig = plt.figure()
        ax = fig.add_subplot(111)
        buckets = 50
        if (len(cfg_diff) == 1):
            buckets = 5
        n, bins, patches = plt.hist(cfg_diff, buckets, normed=0, facecolor='blue', alpha=0.6)
        plt.xlabel(r'$\mathrm{Different\ Subtrace\ Lengths\ (Instructions)}\ $')
        plt.ylabel(r'$\mathrm{Frequency}$')
        string_title = r'$\mathrm{Total\ Instructions:\ ' + str(total_instructions) + '.\ Longest\ Sequence:\ ' + str(max(cfg_diff)) + '.}\ $'        
        ax.annotate(string_title, 
                    (0.20, 0.75), xytext=None, xycoords='data',
                    textcoords='axes fraction', arrowprops=None)
        plt.title(r'$\mathrm{Histogram\ of\ Control\ Flow\ Nondeterminism}\ $')
        plt.axis([max(0, min(cfg_diff)-2), max(1, max(cfg_diff)), 0, len(cfg_diff)])
        plt.grid(True)
        fig.savefig(dest, dpi=300)
    return

def draw_hist_same_truncated(same, total_instructions, dest):
    if len(same) > 0:
        fig = plt.figure()
        ax = fig.add_subplot(111)
        buckets = 50
        if (len(same) == 1):
            buckets = 5
        n, bins, patches = plt.hist(same, buckets, normed=0, facecolor='green', alpha=0.6)
        if not is_skewed(n)[0]:
            return

        plt.xlabel(r'$\mathrm{Identical\ Subtrace\ Lengths\ (Instructions)}\ $')
        plt.ylabel(r'$\mathrm{Frequency}$')
        string_title = r'$\mathrm{Total\ Instructions:\ ' + str(total_instructions) + '.\ Longest\ Sequence:\ ' + str(max(same)) + '.}\ $'        

        ax.annotate(string_title,
                    (0.16, 0.75), xytext=None, xycoords='data',
                    textcoords='axes fraction', arrowprops=None)
        
        #if (n[0] > max(n)):
        #    ax.annotate(r'$\mathrm{Truncated\ (Height\ =\ ' + str(n[0]) + r').}\ $',
        #                (0.02, 0.99), xytext=(0.06, 0.95), xycoords='axes fraction',
        #                textcoords='axes fraction', arrowprops=dict(facecolor='black', width=1.0, headwidth=5.0, alpha=0.5),
        #                horizontalalignment='left', verticalalignment='center',
        #                fontsize=10)
        
        plt.title(r'$\mathrm{Truncated\ Histogram\ of\ Instruction\ Level\ Determinism}\ $')
        plt.axis([max(0, min(same)-2), max(1, max(same)), 0, is_skewed(n)[1]])
        plt.grid(True)
        fig.savefig(dest, dpi=300)
    return

def draw_hist_diff_truncated(diff, total_instructions, dest):
    if len(diff) > 0:
        fig = plt.figure()
        ax = fig.add_subplot(111)
        buckets = 50
        if (len(diff) == 1):
            buckets = 5
        n, bins, patches = plt.hist(diff, buckets, normed=0, facecolor='red', alpha=0.6)
        if not is_skewed(n)[0]:
            return

        plt.xlabel(r'$\mathrm{Conflicting\ Subtrace\ Lengths\ (Instructions)}\ $')
        plt.ylabel(r'$\mathrm{Frequency}$')
        string_title = r'$\mathrm{Total\ Instructions:\ ' + str(total_instructions) + '.\ Longest\ Sequence:\ ' + str(max(diff)) + '.}\ $'        

        ax.annotate(string_title,
                    (0.16, 0.75), xytext=None, xycoords='data',
                    textcoords='axes fraction', arrowprops=None)
        
        #if (n[0] > max_y):
        #    ax.annotate(r'$\mathrm{Truncated\ (Height\ =\ ' + str(n[0]) + r').}\ $',
        #                (0.02, 0.99), xytext=(0.06, 0.95), xycoords='axes fraction',
        #                textcoords='axes fraction', arrowprops=dict(facecolor='black', width=1.0, headwidth=5.0, alpha=0.5),
        #                horizontalalignment='left', verticalalignment='center',
        #                fontsize=10)
        
        plt.title(r'$\mathrm{Truncated\ Histogram\ of\ Instruction\ Level\ Nondeterminism}\ $')
        plt.axis([max(0, min(diff)-2), max(1, max(diff)), 0, is_skewed(n)[1]])
        plt.grid(True)
        fig.savefig(dest, dpi=300)
    return

def draw_hist_cfgdiff_truncated(same, total_instructions, dest):
    if len(same) > 0:
        fig = plt.figure()
        ax = fig.add_subplot(111)
        buckets = 50
        if (len(same) == 1):
            buckets = 5
        n, bins, patches = plt.hist(same, buckets, normed=0, facecolor='blue', alpha=0.6)
        if not is_skewed(n)[0]:
            return        

        plt.xlabel(r'$\mathrm{Different\ Subtrace\ Lengths\ (Instructions)}\ $')
        plt.ylabel(r'$\mathrm{Frequency}$')
        string_title = r'$\mathrm{Total\ Instructions:\ ' + str(total_instructions) + '.\ Longest\ Sequence:\ ' + str(max(same)) + '.}\ $'        

        ax.annotate(string_title,
                    (0.16, 0.75), xytext=None, xycoords='data',
                    textcoords='axes fraction', arrowprops=None)

        #if (n[0] > max_y):
        #    ax.annotate(r'$\mathrm{Truncated\ (Height\ =\ ' + str(n[0]) + r').}\ $',
        #                (0.02, 0.99), xytext=(0.06, 0.95), xycoords='axes fraction',
        #                textcoords='axes fraction', arrowprops=dict(facecolor='black', width=1.0, headwidth=5.0, alpha=0.5),
        #                horizontalalignment='left', verticalalignment='center',
        #                fontsize=10)
        
        plt.title(r'$\mathrm{Truncated\ Histogram\ of\ Control\ Flow\ Nondeterminism}\ $')
        plt.axis([max(0, min(same)-2), max(1, max(same)), 0, is_skewed(n)[1]])
        plt.grid(True)
        fig.savefig(dest, dpi=300)
    return

def draw_trace(intervals1, intervals2, dest, same_percent, prefix_percent, ls_percent):
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
                    
    ax.broken_barh(points1, (10, 10), facecolors=colors1, alpha=0.6, linewidth=0.05)
    ax.broken_barh(points2, (35, 10), facecolors=colors2, alpha=0.6, linewidth=0.05)
    
    ax.set_ylim(0,50)
    ax.set_xlim(0, max(intervals1[-1][1], intervals2[-1][1]))
    ax.set_xlabel(r'$\mathrm{Instructions\ Executed}$')
    ax.set_yticks([15,40])
    ax.set_yticklabels([r'$\mathrm{Instance\ 1}$', '$\mathrm{Instance\ 2}$'])
    ax.grid(True)

    ax.set_title(r'$\mathrm{Program\ Execution\ Visualization}$')

    string_title = r'$\mathrm{Total\ Determinism:\ ' + str(same_percent) + '\%.}\ $'
    ax.annotate(string_title,
                (0.31, 0.53), xytext=None, xycoords='data',
                textcoords='axes fraction', arrowprops=None)
    string_title = r'$\mathrm{Common\ Prefix:\ ' + str(prefix_percent) + '\%.\ Longest\ Common\ Substring:\ ' + str(ls_percent) + '\%}.\ $'
    ax.annotate(string_title,
                (0.13, 0.47), xytext=None, xycoords='data',
                textcoords='axes fraction', arrowprops=None)

    fig.savefig(dest, dpi=300)
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
    prefix = -1

    while (line != ''):
        A_new_interval = None
        B_new_interval = None
        
        if line.find('<') != -1 and line.find('>') != -1:
            # rdtsc bug
            A_new_interval = (index, index+1, SAME)
            B_new_interval = (index, index+1, SAME)
            same += 1
        elif line.find('|') != -1:
            A_new_interval = (index, index+1, CONFLICT)
            B_new_interval = (index, index+1, CONFLICT)
            conflicts += 1
            if (prefix == -1):
                prefix = index + 1

        elif line.find('<') != -1:
            A_new_interval = (index, index+1, ONLY_ME)
            onlyA += 1
            if (prefix == -1):
                prefix = index + 1
        elif line.find('>') != -1:
            B_new_interval = (index, index+1, ONLY_ME)
            onlyB += 1
            if (prefix == -1):
                prefix = index + 1
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

    if (prefix == -1):
        prefix = index;

    handle.close()
    
    max_same = 0
    for start, end, type in A_intervals:
        if (end-start) > max_same:
            max_same = (end-start)

    print get_time() + ' preliminary analysis results:'
    print '\t\t total lines: ' + str(index)
    print '\t\t total conflicts: ' + str(conflicts)
    print '\t\t total only in A: ' + str(onlyA)
    print '\t\t total only in B: ' + str(onlyB)
    print '\t\t total same: ' + str(same)
    print '\t\t common prefix: ' + str(prefix)
    
    same_percent = 100.0*float(same)/float(index)
    same_percent = "%.2f" % same_percent

    conflict_percent = 100.0*float(conflicts)/float(index)
    conflict_percent = "%.2f" % conflict_percent

    prefix_percent = 100.0*float(prefix)/float(index)
    prefix_percent = "%.2f" % prefix_percent

    lcs_percent = 100.0*float(max_same/float(index))
    lcs_percent = "%.2f" % lcs_percent

    print
    print '\t\t same %age = ' + str(same_percent) + ' percent'
    print '\t\t conflict %age = ' +  str(conflict_percent) + ' percent'
    print '\t\t prefix %age = ' +  str(prefix_percent) + ' percent'
    print '\t\t longest common substring %age = ' +  str(lcs_percent) + ' percent'

    return A_intervals, B_intervals, same_percent, prefix_percent, lcs_percent

def main(args):
    if len(args) != 2:
        print 'usage: binary {diff_file} {figures_folder with /}'
        return
    else:
        print get_time() + ' starting analysis of diff file'
        intervals1, intervals2, same_percent, prefix_percent, ls_percent = compute_diff(args[0], args[1])

        print get_time() + ' starting trace drawing'
        draw_trace(intervals1, intervals2, args[1] + 'trace.pdf', same_percent, prefix_percent, ls_percent)

        print get_time() + ' starting histograms'
        draw_histograms(intervals1, intervals2, args[1])

        print get_time() + ' done'
        return
    
if __name__ == "__main__":
    main(sys.argv[1:])
    
