#!/usr/bin/env python
import sys

def main(args):
    if len(args) != 4:
        print 'usage: binary {file1} {file2} {Nth diff} {L context lines}'
        return
    else:
        f1 = open(args[0])
        f2 = open(args[1])
        N = int(args[2])
        L = int(args[3])

        diffs_seen = 0
        num_lines = 0

        while(True):
            line1 = f1.readline()
            line2 = f2.readline()
            if (line1 == '' or line2 == ''):
                print '*** WARNING: Reached end of file. Recheck input parameters ***'
                return
            if (line1 != line2):
                diffs_seen += 1
                if (diffs_seen == N):
                    break
            num_lines += 1 

        f1.close()
        f2.close()

        print 'Found ' + str(N) + 'th diff at line = ' + str(num_lines)
                
        f1 = open(args[0])
        f2 = open(args[1])
        print 'Rescanning files for context'

        current_line = 0
        window_start = num_lines - L
        window_end = num_lines + L
        
        lines1 = []
        lines2 = []

        while(True):
            line1 = f1.readline()
            line2 = f2.readline()
            if (line1 == '' or line2 == ''):
                break
            if (current_line > window_end):
                return
            if (current_line >= window_start):
                if (current_line == num_lines):
                    lines1.append('*** ' + line1[:-1])
                    lines2.append('*** ' + line2[:-1])
                elif (line1 == line2):
                    lines1.append('>   ' + line1[:-1])
                    lines2.append('<   ' + line2[:-1])
                else:
                    lines1.append('>>  ' + line1[:-1])
                    lines2.append('<<  ' + line2[:-1])
            current_line += 1 

        f1.close()
        f2.close()

        print 'Dumping context'
        
        print
        for line in lines1:
            print line
        
        print 
        for line in lines2:
            print line

        print 'Done'
        return
        
if __name__ == "__main__":
    main(sys.argv[1:])
    
