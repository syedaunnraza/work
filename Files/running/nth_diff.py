#!/usr/bin/env python
import sys

spaces = []

def main(args):

    num_spaces = 0
    current = ''
    while (num_spaces < 150):
        spaces.append(current)
        num_spaces += 1
        current += ' '

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
                print '*** < NUM LINES = ' + str(num_lines) + '> ***'
                
                return
            if (line1 != line2):
                diffs_seen += 1
                if (diffs_seen == N):
                    break
            num_lines += 1 

        f1.close()
        f2.close()

        print 'found diff #' + str(N) + ' at line = ' + str(num_lines)
                
        f1 = open(args[0])
        f2 = open(args[1])

        lines1 = []
        lines2 = []
        combined_lines = []

        current_line = 0
        window_start = num_lines - L
        window_end = num_lines + L

        print 'rescanning files for context from lines: [' + str(window_start) + ' - ' + str(window_end) + ']'

        while(True):
            line1 = f1.readline()
            line2 = f2.readline()
            if (line1 == '' or line2 == ''):
                break
            if line1[0] == '\t':
                line1 = line1[1:]
            if line2[0] == '\t':
                line2 = line2[1:]
            if (current_line > window_end):
                break
            if (current_line >= window_start):
                if (current_line == num_lines):
                    lines1.append('*** ' + line1[:-1])
                    lines2.append('*** ' + line2[:-1])
                    
                    needed_spaces = 100 - len(line1[:-1])
                    if (needed_spaces > 0):
                        filler = spaces[needed_spaces]
                    combined_line = line1[:-1] + filler + '  ||  ' + line2[:-1]
                    combined_lines.append(combined_line)
                elif (line1 == line2):
                    lines1.append('>   ' + line1[:-1])
                    lines2.append('<   ' + line2[:-1])

                    needed_spaces = 100 - len(line1[:-1])
                    if (needed_spaces > 0):
                        filler = spaces[needed_spaces]
                    combined_line = line1[:-1] + filler + '  ==  ' + line2[:-1]
                    combined_lines.append(combined_line)
                else:
                    lines1.append('>>  ' + line1[:-1])
                    lines2.append('<<  ' + line2[:-1])
                    needed_spaces = 100 - len(line1[:-1])

                    if (needed_spaces > 0):
                        filler = spaces[needed_spaces]
                    combined_line = line1[:-1] + filler + '  <>  ' + line2[:-1]
                    combined_lines.append(combined_line)

            current_line += 1 

        f1.close()
        f2.close()

        print 'dumping context:'
        print

        print
        for line in lines1:
            print line
        
        print 
        for line in lines2:
            print line

        print 
        for line in combined_lines:
            print line
        print
        print 'Done'
        return
        
if __name__ == "__main__":
    main(sys.argv[1:])
    
