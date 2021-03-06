#!/usr/bin/env python
import sys

def main(args):
    if len(args) != 4:
        print 'usage: binary {old log 1} {old log 2} {new log 1} {new log 2}'
        return
    else:
        f1 = open(args[0])
        f2 = open(args[1])
        f3 = open(args[2], 'w')
        f4 = open(args[3], 'w')

        #num_lines = 0
        #while(True):
        #    line1 = f1.readline()
        #    line2 = f2.readline()
        #    if (line1 == '' or line2 == ''):
        #        break
        #    num_lines += 1
            
        #print '*** min(#lines1, #lines2) = ' + str(num_lines) + ' lines ***'
            
        #f1.close()
        #f2.close()
        #f1 = open(args[0])
        #f2 = open(args[1])

        num_lines = 0
        while(True):
            line1 = f1.readline()
            line2 = f2.readline()

            if (line1 == '' or line2 == ''):
                break
                print '*** Found first divergence after<' + str(num_lines) + '> lines ***'
                
            if (line1 != line2):
                print '*** Found first divergence after<' + str(num_lines) + '> lines ***'
                break

            num_lines += 1

        print '*** Writing residual stuff to files ***'
        num_lines = 0
        while(True):
            # line1 and line2 are the same
            if line1 != '':
                f3.write(line1)
            if line2 != '':
                f4.write(line2)
            if (line1 == '' and line2 == ''):
                break
            num_lines += 1
            line1 = f1.readline()
            line2 = f2.readline()
        
        print '*** Wrote ' + str(num_lines) + ' lines in residual files ***'

        f1.close()
        f2.close()
        f3.close()
        f4.close()

        print '*** Done ***'
        return
        
if __name__ == "__main__":
    main(sys.argv[1:])
    
