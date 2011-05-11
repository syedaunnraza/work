#!/usr/bin/env python
import sys

def main(args):
    if len(args) != 2:
        print 'usage: binary {file1} {file2}'
        return
    else:
        f1 = open(args[0])
        f2 = open(args[1])

        diff_lines = 0
        common_prefix = 0
        done_prefix = False
        num_lines = 0

        while(True):
            line1 = f1.readline()
            line2 = f2.readline()
            if (line1 == '' or line2 == ''):
                break
            if (line1 != line2):
                diff_lines += 1
                if(not done_prefix):
                    common_prefix = num_lines
                    done_prefix = True

            num_lines += 1 

        if (not done_prefix):
            common_prefix = num_lines

        f1.close()
        f2.close()

        print 'there are ' + str(num_lines) + ' under consideration'
        print 'there are ' + str(common_prefix) + ' lines in common prefix'
        print 'there are ' + str(diff_lines) + ' different lines'
        print
        
        f1 = open(args[0])
        f2 = open(args[1])

        previousline1 = ""
        previousline2 = ""
        while(True):
            line1 = f1.readline()
            line2 = f2.readline()
            if (line1 == '' or line2 == ''):
                break
            if (line1 != line2):
                print '>  ' + previousline1[:-1]
                print '>> ' + line1[:-1]
                print '<  ' + previousline2[:-1]
                print '<< ' + line2[:-1]
                print

            num_lines += 1 
            previousline1 = line1
            previousline2 = line2

        if (not done_prefix):
            common_prefix = num_lines

        f1.close()
        f2.close()
        
if __name__ == "__main__":
    main(sys.argv[1:])
    
